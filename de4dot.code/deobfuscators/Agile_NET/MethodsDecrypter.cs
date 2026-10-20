/*
    Copyright (C) 2011-2015 de4dot@gmail.com

    This file is part of de4dot.

    de4dot is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    de4dot is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with de4dot.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.IO;
using dnlib.IO;
using dnlib.PE;
using dnlib.DotNet;
using dnlib.DotNet.MD;
using de4dot.blocks;

namespace de4dot.code.deobfuscators.Agile_NET {
	class CodeHeader {
		public byte[] signature;
		public byte[] decryptionKey;
		public uint totalCodeSize;
		public uint numMethods;
		public uint methodDefTableOffset;	// Relative to start of metadata
		public uint methodDefElemSize;
	}

	struct MethodInfo {
		public uint codeOffs, codeSize, flags, localVarSigTok;

		public MethodInfo(uint codeOffs, uint codeSize, uint flags, uint localVarSigTok) {
			this.codeOffs = codeOffs;
			this.codeSize = codeSize;
			this.flags = flags;
			this.localVarSigTok = localVarSigTok;
		}

		public override string ToString() => $"{codeOffs:X8} {codeSize:X8} {flags:X8} {localVarSigTok:X8}";
	}

	class MethodsDecrypter {
		static readonly byte[] oldSignature    = new byte[16] { 0x1F, 0x68, 0x9D, 0x2B, 0x07, 0x4A, 0xA6, 0x4A, 0x92, 0xBB, 0x31, 0x7E, 0x60, 0x7F, 0xD7, 0xCD };
		static readonly byte[] normalSignature = new byte[16] { 0x08, 0x44, 0x65, 0xE1, 0x8C, 0x82, 0x13, 0x4C, 0x9C, 0x85, 0xB4, 0x17, 0xDA, 0x51, 0xAD, 0x25 };
		static readonly byte[] proSignature    = new byte[16] { 0x68, 0xA0, 0xBB, 0x60, 0x13, 0x65, 0x5F, 0x41, 0xAE, 0x42, 0xAB, 0x42, 0x9B, 0x6B, 0x4E, 0xC1 };

		enum SigType {
			Unknown,
			Old,
			Normal,
			Pro,
		}

		MyPEImage peImage;
		ModuleDefMD module;
		CliSecureRtType csRtType;
		CodeHeader codeHeader = new CodeHeader();
		IDecrypter decrypter;
		SigType sigType;

		interface IDecrypter {
			MethodBodyHeader Decrypt(MethodInfo methodInfo, out byte[] code, out byte[] extraSections);
		}

		abstract class DecrypterBase : IDecrypter {
			protected readonly MyPEImage peImage;
			protected readonly CodeHeader codeHeader;
			protected readonly uint endOfMetadata;

			public DecrypterBase(MyPEImage peImage, CodeHeader codeHeader) {
				this.peImage = peImage;
				this.codeHeader = codeHeader;
				var mdDir = peImage.Cor20Header.Metadata;
				endOfMetadata = peImage.RvaToOffset((uint)mdDir.VirtualAddress + mdDir.Size);
			}

			public abstract MethodBodyHeader Decrypt(MethodInfo methodInfo, out byte[] code, out byte[] extraSections);

			protected MethodBodyHeader GetCodeBytes(byte[] methodBody, out byte[] code, out byte[] extraSections) {
				var reader = ByteArrayDataReaderFactory.CreateReader(methodBody);
				return MethodBodyParser.ParseMethodBody(ref reader, out code, out extraSections);
			}
		}

		// CS 1.1 (could be other versions too)
		class Decrypter10 {
			MyPEImage peImage;
			CsBlowfish blowfish;

			public Decrypter10(MyPEImage peImage, byte[] key) {
				this.peImage = peImage;
				blowfish = new CsBlowfish(key);
			}

			public MethodBodyHeader Decrypt(uint bodyOffset, out byte[] code, out byte[] extraSections) {
				peImage.Reader.Position = bodyOffset;
				var mbHeader = MethodBodyParser.ParseMethodBody(ref peImage.Reader, out code, out extraSections);
				blowfish.Decrypt(code);
				return mbHeader;
			}
		}

		// CS 3.0 (could be other versions too)
		class Decrypter30 : DecrypterBase {
			public Decrypter30(MyPEImage peImage, CodeHeader codeHeader)
				: base(peImage, codeHeader) {
			}

			public override MethodBodyHeader Decrypt(MethodInfo methodInfo, out byte[] code, out byte[] extraSections) {
				peImage.Reader.Position = peImage.RvaToOffset(methodInfo.codeOffs);
				return MethodBodyParser.ParseMethodBody(ref peImage.Reader, out code, out extraSections);
			}
		}

		// CS 4.0 (could be other versions too)
		class Decrypter40 : DecrypterBase {
			public Decrypter40(MyPEImage peImage, CodeHeader codeHeader)
				: base(peImage, codeHeader) {
			}

			public override MethodBodyHeader Decrypt(MethodInfo methodInfo, out byte[] code, out byte[] extraSections) {
				peImage.Reader.Position = endOfMetadata + methodInfo.codeOffs;
				return MethodBodyParser.ParseMethodBody(ref peImage.Reader, out code, out extraSections);
			}
		}

		// CS 4.5 (could be other versions too)
		class Decrypter45 : DecrypterBase {
			public Decrypter45(MyPEImage peImage, CodeHeader codeHeader)
				: base(peImage, codeHeader) {
			}

			public override MethodBodyHeader Decrypt(MethodInfo methodInfo, out byte[] code, out byte[] extraSections) {
				var data = peImage.OffsetReadBytes(endOfMetadata + methodInfo.codeOffs, (int)methodInfo.codeSize);
				for (int i = 0; i < data.Length; i++) {
					byte b = data[i];
					b ^= codeHeader.decryptionKey[(methodInfo.codeOffs - 0x28 + i) % 16];
					data[i] = b;
				}
				return GetCodeBytes(data, out code, out extraSections);
			}
		}

		// CS 5.0+
		class Decrypter5 : DecrypterBase {
			readonly uint codeHeaderSize;
			readonly byte[] v52RecoveredKey;

			public Decrypter5(MyPEImage peImage, CodeHeader codeHeader, uint codeHeaderSize)
				: base(peImage, codeHeader) => this.codeHeaderSize = codeHeaderSize;

			public Decrypter5(MyPEImage peImage, CodeHeader codeHeader, uint codeHeaderSize, byte[] recoveredKey)
				: this(peImage, codeHeader, codeHeaderSize) => v52RecoveredKey = recoveredKey;

			public byte[] GetDecryptedBytes(MethodInfo methodInfo, out uint fileOffset) {
				fileOffset = endOfMetadata + methodInfo.codeOffs;
				byte[] data = peImage.OffsetReadBytes(fileOffset, (int)methodInfo.codeSize);
				for (int i = 0; i < data.Length; i++) {
					if (v52RecoveredKey != null) {
						data[i] ^= v52RecoveredKey[(int)((methodInfo.codeOffs + (uint)i) & 15)];
						continue;
					}
					byte b = data[i];
					b ^= codeHeader.decryptionKey[(methodInfo.codeOffs - codeHeaderSize + i) % 16];
					b ^= codeHeader.decryptionKey[(methodInfo.codeOffs - codeHeaderSize + i + 7) % 16];
					data[i] = b;
				}
				return data;
			}

			public bool TryParseDiagnostic(byte[] data, out string error) {
				try {
					byte[] code, extraSections;
					GetCodeBytes(data, out code, out extraSections);
					error = null;
					return true;
				}
				catch (Exception ex) {
					error = ex.GetType().Name;
					return false;
				}
			}

			public override MethodBodyHeader Decrypt(MethodInfo methodInfo, out byte[] code, out byte[] extraSections) {
				uint fileOffset;
				byte[] data = GetDecryptedBytes(methodInfo, out fileOffset);
				byte[] prefixBefore = peImage.OffsetReadBytes(fileOffset, Math.Min(data.Length, 16));
			try {
					return GetCodeBytes(data, out code, out extraSections);
				}
				catch (InvalidMethodBody) {
					int prefixLength = Math.Min(data.Length, 16);
					byte header = data.Length == 0 ? (byte)0 : data[0];
					string headerKind = data.Length == 0 ? "empty" : (header & 3) == 2 ? "tiny" : (header & 7) == 3 ? "fat" : "invalid";
					Logger.n($"Agile.NET Decrypter5: absolute file offset=0x{fileOffset:X8}, encrypted length={data.Length}, header kind={headerKind}, first byte=0x{header:X2}");
					Logger.n($"Agile.NET Decrypter5: encrypted prefix ({prefixBefore.Length} bytes): {BitConverter.ToString(prefixBefore)}");
					Logger.n($"Agile.NET Decrypter5: decrypted prefix ({prefixLength} bytes): {BitConverter.ToString(data, 0, prefixLength)}");
					throw;
				}
			}
		}

		// CS 5.4+. Used when the anti-debugger protection is enabled
		class ProDecrypter : DecrypterBase {
			readonly uint[] key = new uint[4];

			public ProDecrypter(MyPEImage peImage, CodeHeader codeHeader)
				: base(peImage, codeHeader) {
				for (int i = 0; i < 4; i++)
					key[i] = ReadUInt32_be(codeHeader.decryptionKey, i * 4);
			}

			public override MethodBodyHeader Decrypt(MethodInfo methodInfo, out byte[] code, out byte[] extraSections) {
				byte[] data = peImage.OffsetReadBytes(endOfMetadata + methodInfo.codeOffs, (int)methodInfo.codeSize);

				int numQwords = (int)(methodInfo.codeSize / 8);
				for (int i = 0; i < numQwords; i++) {
					int offset = i * 8;
					uint q0 = ReadUInt32_be(data, offset);
					uint q1 = ReadUInt32_be(data, offset + 4);

					const uint magic = 0x9E3779B8;
					uint val = 0xC6EF3700;	// magic * 0x20
					for (int j = 0; j < 32; j++) {
						q1 -= ((q0 << 4) + key[2]) ^ (val + q0) ^ ((q0 >> 5) + key[3]);
						q0 -= ((q1 << 4) + key[0]) ^ (val + q1) ^ ((q1 >> 5) + key[1]);
						val -= magic;
					}

					WriteUInt32_be(data, offset, q0);
					WriteUInt32_be(data, offset + 4, q1);
				}

				return GetCodeBytes(data, out code, out extraSections);
			}

			static uint ReadUInt32_be(byte[] data, int offset) =>
				(uint)((data[offset] << 24) +
						(data[offset + 1] << 16) +
						(data[offset + 2] << 8) +
						data[offset + 3]);

			static void WriteUInt32_be(byte[] data, int offset, uint value) {
				data[offset] = (byte)(value >> 24);
				data[offset + 1] = (byte)(value >> 16);
				data[offset + 2] = (byte)(value >> 8);
				data[offset + 3] = (byte)value;
			}
		}

		interface ICsHeader {
			IDecrypter CreateDecrypter();
			List<MethodInfo> GetMethodInfos(uint codeHeaderOffset);
			void PatchMethodTable(MDTable methodDefTable, IList<MethodInfo> methodInfos);
		}

		abstract class CsHeaderBase : ICsHeader {
			protected readonly MethodsDecrypter methodsDecrypter;
			protected readonly uint codeHeaderSize;

			public CsHeaderBase(MethodsDecrypter methodsDecrypter, uint codeHeaderSize) {
				this.methodsDecrypter = methodsDecrypter;
				this.codeHeaderSize = codeHeaderSize;
			}

			public abstract IDecrypter CreateDecrypter();

			public virtual void PatchMethodTable(MDTable methodDefTable, IList<MethodInfo> methodInfos) {
			}

			public abstract List<MethodInfo> GetMethodInfos(uint codeHeaderOffset);

			protected List<MethodInfo> GetMethodInfos1(uint codeHeaderOffset) {
				uint offset = codeHeaderOffset + methodsDecrypter.codeHeader.totalCodeSize + codeHeaderSize;
				var methodInfos = new List<MethodInfo>((int)methodsDecrypter.codeHeader.numMethods);
				for (int i = 0; i < (int)methodsDecrypter.codeHeader.numMethods; i++, offset += 4) {
					uint codeOffs = methodsDecrypter.peImage.OffsetReadUInt32(offset);
					methodInfos.Add(new MethodInfo(codeOffs, 0, 0, 0));
				}
				return methodInfos;
			}

			protected List<MethodInfo> GetMethodInfos2(uint codeHeaderOffset) {
				uint offset = codeHeaderOffset + methodsDecrypter.codeHeader.totalCodeSize + codeHeaderSize;
				var methodInfos = new List<MethodInfo>((int)methodsDecrypter.codeHeader.numMethods);
				for (int i = 0; i < (int)methodsDecrypter.codeHeader.numMethods; i++, offset += 8) {
					uint codeOffs = methodsDecrypter.peImage.OffsetReadUInt32(offset);
					uint codeSize = methodsDecrypter.peImage.OffsetReadUInt32(offset + 4);
					methodInfos.Add(new MethodInfo(codeOffs, codeSize, 0, 0));
				}
				return methodInfos;
			}

			protected List<MethodInfo> GetMethodInfos4(uint codeHeaderOffset) {
				uint offset = codeHeaderOffset + methodsDecrypter.codeHeader.totalCodeSize + codeHeaderSize;
				var methodInfos = new List<MethodInfo>((int)methodsDecrypter.codeHeader.numMethods);
				for (int i = 0; i < (int)methodsDecrypter.codeHeader.numMethods; i++, offset += 16) {
					uint codeOffs = methodsDecrypter.peImage.OffsetReadUInt32(offset);
					uint codeSize = methodsDecrypter.peImage.OffsetReadUInt32(offset + 4);
					uint flags = methodsDecrypter.peImage.OffsetReadUInt32(offset + 8);
					uint localVarSigTok = methodsDecrypter.peImage.OffsetReadUInt32(offset + 12);
					methodInfos.Add(new MethodInfo(codeOffs, codeSize, flags, localVarSigTok));
				}
				return methodInfos;
			}
		}

		// CS 3.0 (could be other versions too)
		class CsHeader30 : CsHeaderBase {
			public CsHeader30(MethodsDecrypter methodsDecrypter)
				: base(methodsDecrypter, 0x28) {
			}

			public override IDecrypter CreateDecrypter() => new Decrypter30(methodsDecrypter.peImage, methodsDecrypter.codeHeader);
			public override List<MethodInfo> GetMethodInfos(uint codeHeaderOffset) => GetMethodInfos1(codeHeaderOffset);
		}

		// CS 4.0 (could be other versions too)
		class CsHeader40 : CsHeaderBase {
			public CsHeader40(MethodsDecrypter methodsDecrypter)
				: base(methodsDecrypter, 0x28) {
			}

			public override IDecrypter CreateDecrypter() => new Decrypter40(methodsDecrypter.peImage, methodsDecrypter.codeHeader);
			public override List<MethodInfo> GetMethodInfos(uint codeHeaderOffset) => GetMethodInfos1(codeHeaderOffset);
		}

		// CS 4.5 (could be other versions too)
		class CsHeader45 : CsHeaderBase {
			public CsHeader45(MethodsDecrypter methodsDecrypter)
				: base(methodsDecrypter, 0x28) {
			}

			public override IDecrypter CreateDecrypter() => new Decrypter45(methodsDecrypter.peImage, methodsDecrypter.codeHeader);
			public override List<MethodInfo> GetMethodInfos(uint codeHeaderOffset) => GetMethodInfos2(codeHeaderOffset);
		}

		// CS 5.0+
		class CsHeader5 : CsHeaderBase {
			public CsHeader5(MethodsDecrypter methodsDecrypter, uint codeHeaderSize)
				: base(methodsDecrypter, codeHeaderSize) {
			}

			public override IDecrypter CreateDecrypter() {
				switch (GetSigType(methodsDecrypter.codeHeader.signature)) {
				case SigType.Normal:
					return new Decrypter5(methodsDecrypter.peImage, methodsDecrypter.codeHeader, codeHeaderSize);

				case SigType.Pro:
					return new ProDecrypter(methodsDecrypter.peImage, methodsDecrypter.codeHeader);

				case SigType.Unknown:
				default:
					throw new ArgumentException("sig");
				}
			}

			public override List<MethodInfo> GetMethodInfos(uint codeHeaderOffset) {
				if (codeHeaderSize == 0x28)
					return GetMethodInfos2(codeHeaderOffset);
				return GetMethodInfos4(codeHeaderOffset);
			}

			public override void PatchMethodTable(MDTable methodDefTable, IList<MethodInfo> methodInfos) {
				uint offset = (uint)methodDefTable.StartOffset - methodDefTable.RowSize;
				foreach (var methodInfo in methodInfos) {
					offset += methodDefTable.RowSize;
					if (methodInfo.flags == 0 || methodInfo.codeOffs == 0)
						continue;
					uint rva = methodsDecrypter.peImage.OffsetReadUInt32(offset);
					methodsDecrypter.peImage.WriteUInt16(rva, (ushort)methodInfo.flags);
					methodsDecrypter.peImage.WriteUInt32(rva + 8, methodInfo.localVarSigTok);
				}
			}
		}

		enum CsHeaderVersion {
			Unknown,
			V10,
			V30,
			V40,
			V45,
			V50,	// 5.0, possibly also 5.1
			V52,	// 5.2+ (or maybe 5.1+)
		}

		List<CsHeaderVersion> GetCsHeaderVersions(uint codeHeaderOffset, MDTable methodDefTable) {
			if (sigType == SigType.Old)
				return new List<CsHeaderVersion> { CsHeaderVersion.V10 };
			if (!IsOldHeader(methodDefTable))
				return new List<CsHeaderVersion> { CsHeaderVersion.V52 };
			if (csRtType.IsAtLeastVersion50())
				return new List<CsHeaderVersion> { CsHeaderVersion.V50 };
			if (IsCsHeader40(codeHeaderOffset)) {
				return new List<CsHeaderVersion> {
					CsHeaderVersion.V40,
					CsHeaderVersion.V30,
				};
			}
			return new List<CsHeaderVersion> {
				CsHeaderVersion.V45,
				CsHeaderVersion.V50,
			};
		}

		bool IsCsHeader40(uint codeHeaderOffset) {
			try {
				uint offset = codeHeaderOffset + codeHeader.totalCodeSize + 0x28;
				uint prevCodeOffs = 0;
				for (int i = 0; i < (int)codeHeader.numMethods; i++, offset += 4) {
					uint codeOffs = peImage.OffsetReadUInt32(offset);
					if (prevCodeOffs != 0 && codeOffs != 0 && codeOffs < prevCodeOffs)
						return false;
					if (codeOffs != 0)
						prevCodeOffs = codeOffs;
				}

				return true;
			}
			catch (Exception ex) when (ex is IOException || ex is ArgumentException) {
				return false;
			}
		}

		bool IsOldHeader(MDTable methodDefTable) {
			if (methodDefTable.RowSize != codeHeader.methodDefElemSize)
				return true;
			if ((uint)methodDefTable.StartOffset - peImage.RvaToOffset((uint)peImage.Cor20Header.Metadata.VirtualAddress) != codeHeader.methodDefTableOffset)
				return true;

			return false;
		}

		ICsHeader CreateCsHeader(CsHeaderVersion version) {
			switch (version) {
			case CsHeaderVersion.V30: return new CsHeader30(this);
			case CsHeaderVersion.V40: return new CsHeader40(this);
			case CsHeaderVersion.V45: return new CsHeader45(this);
			case CsHeaderVersion.V50: return new CsHeader5(this, 0x28);
			case CsHeaderVersion.V52: return new CsHeader5(this, 0x30);
			default: throw new ApplicationException("Unknown CS header");
			}
		}

		enum DecryptResult {
			NotEncrypted,
			Decrypted,
			Error,
		}

		public bool Decrypt(MyPEImage peImage, ModuleDefMD module, CliSecureRtType csRtType, ref DumpedMethods dumpedMethods) {
			this.peImage = peImage;
			this.csRtType = csRtType;
			this.module = module;

			switch (Decrypt2(ref dumpedMethods)) {
			case DecryptResult.Decrypted: return true;
			case DecryptResult.NotEncrypted: return false;

			case DecryptResult.Error:
				Logger.n("Using dynamic method decryption");
				byte[] moduleCctorBytes = GetModuleCctorBytes(csRtType);
				dumpedMethods = de4dot.code.deobfuscators.MethodsDecrypter.Decrypt(module, moduleCctorBytes);
				return true;

			default:
				throw new ApplicationException("Invalid DecryptResult");
			}
		}

		static byte[] GetModuleCctorBytes(CliSecureRtType csRtType) {
			var initMethod = csRtType.InitializeMethod;
			if (initMethod == null)
				return null;
			uint initToken = initMethod.MDToken.ToUInt32();
			var moduleCctorBytes = new byte[6];
			moduleCctorBytes[0] = 0x28;	// call
			moduleCctorBytes[1] = (byte)initToken;
			moduleCctorBytes[2] = (byte)(initToken >> 8);
			moduleCctorBytes[3] = (byte)(initToken >> 16);
			moduleCctorBytes[4] = (byte)(initToken >> 24);
			moduleCctorBytes[5] = 0x2A;	// ret
			return moduleCctorBytes;
		}

		static uint GetCodeHeaderOffset(MyPEImage peImage) =>
			peImage.RvaToOffset((uint)peImage.Cor20Header.Metadata.VirtualAddress + peImage.Cor20Header.Metadata.Size);

		static string[] sections = new string[] {
			".text", ".rsrc", ".data", ".rdata",
		};
		static uint GetOldCodeHeaderOffset(MyPEImage peImage) {
			var sect = GetLastOf(peImage, sections);
			if (sect == null || sect.VirtualSize < 0x100)
				return 0;
			return peImage.RvaToOffset((uint)sect.VirtualAddress + sect.VirtualSize - 0x100);
		}

		static ImageSectionHeader GetLastOf(MyPEImage peImage, string[] sections) {
			ImageSectionHeader sect = null;
			foreach (var name in sections) {
				var sect2 = peImage.FindSection(name);
				if (sect2 == null)
					continue;
				if (sect == null || sect2.VirtualAddress > sect.VirtualAddress)
					sect = sect2;
			}
			return sect;
		}

		DecryptResult Decrypt2(ref DumpedMethods dumpedMethods) {
			uint codeHeaderOffset = InitializeCodeHeader();
			if (sigType == SigType.Unknown)
				return DecryptResult.NotEncrypted;

			var methodDefTable = peImage.Metadata.TablesStream.MethodTable;
			uint metadataOffset = peImage.RvaToOffset((uint)peImage.Cor20Header.Metadata.VirtualAddress);
			uint actualMethodDefOffset = (uint)methodDefTable.StartOffset - metadataOffset;
			Logger.n($"Agile.NET header: signature={sigType}, offset=0x{codeHeaderOffset:X8}, codeSize=0x{codeHeader.totalCodeSize:X8}, methodCount={codeHeader.numMethods}");
			Logger.n($"Agile.NET header: stored MethodDef offset=0x{codeHeader.methodDefTableOffset:X8}, rowSize={codeHeader.methodDefElemSize}; actual offset=0x{actualMethodDefOffset:X8}, rowSize={methodDefTable.RowSize}, rows={methodDefTable.Rows}");
			Logger.n($"Agile.NET header: calculated V52 table offset=0x{(codeHeaderOffset + codeHeader.totalCodeSize + 0x30u):X8}, V52 index size={(ulong)codeHeader.numMethods * 16} bytes");

			foreach (var version in GetCsHeaderVersions(codeHeaderOffset, methodDefTable)) {
				try {
					Logger.n($"Agile.NET static decryption: trying {version} (header offset 0x{codeHeaderOffset:X8}, methods {codeHeader.numMethods})");
					if (version == CsHeaderVersion.V10)
						DecryptMethodsOld(methodDefTable, ref dumpedMethods);
					else
						DecryptMethods(codeHeaderOffset, methodDefTable, CreateCsHeader(version), ref dumpedMethods);
					Logger.n($"Agile.NET static decryption: {version} succeeded");
					return DecryptResult.Decrypted;
				}
				catch (Exception ex) {
					Logger.n($"Agile.NET static decryption: {version} failed: {ex}");
				}
			}

			return DecryptResult.Error;
		}

		uint InitializeCodeHeader() {
			uint codeHeaderOffset = GetCodeHeaderOffset(peImage);
			ReadCodeHeader(codeHeaderOffset);
			sigType = GetSigType(codeHeader.signature);

			if (sigType == SigType.Unknown) {
				codeHeaderOffset = GetOldCodeHeaderOffset(peImage);
				if (codeHeaderOffset != 0) {
					ReadCodeHeader(codeHeaderOffset);
					sigType = GetSigType(codeHeader.signature);
				}
			}

			return codeHeaderOffset;
		}

		void DecryptMethodsOld(MDTable methodDefTable, ref DumpedMethods dumpedMethods) {
			dumpedMethods = new DumpedMethods();
			var decrypter = new Decrypter10(peImage, codeHeader.decryptionKey);
			for (uint rid = 1; rid <= methodDefTable.Rows; rid++) {
				var dm = new DumpedMethod();

				var method = (MethodDef)module.ResolveMethod(rid);
				if (method == null || method.DeclaringType == module.GlobalType)
					continue;

				peImage.ReadMethodTableRowTo(dm, rid);
				if (dm.mdRVA == 0)
					continue;
				uint bodyOffset = peImage.RvaToOffset(dm.mdRVA);

				var mbHeader = decrypter.Decrypt(bodyOffset, out dm.code, out dm.extraSections);
				peImage.UpdateMethodHeaderInfo(dm, mbHeader);

				dumpedMethods.Add(dm);
			}
		}

		void DecryptMethods(uint codeHeaderOffset, MDTable methodDefTable, ICsHeader csHeader, ref DumpedMethods dumpedMethods) {
			var methodInfos = csHeader.GetMethodInfos(codeHeaderOffset);
			int logged = Math.Min(methodInfos.Count, 12);
			for (int i = 0; i < logged; i++) {
				var info = methodInfos[i];
				ulong end = (ulong)info.codeOffs + info.codeSize;
				string rangeStatus = info.codeOffs == 0 ? "absent" : end <= codeHeader.totalCodeSize ? "within declared region" : "OUTSIDE declared region";
				Logger.n($"Agile.NET V52 index: RID {i + 1}, offset=0x{info.codeOffs:X8}, size={info.codeSize}, end=0x{end:X8}, {rangeStatus}");
			}
			int present = 0;
			int outside = 0;
			for (int i = 0; i < methodInfos.Count; i++) {
				var info = methodInfos[i];
				if (info.codeOffs == 0)
					continue;
				present++;
				if ((ulong)info.codeOffs + info.codeSize > codeHeader.totalCodeSize)
					outside++;
			}
			Logger.n($"Agile.NET V52 index: present={present}, absent={methodInfos.Count - present}, outside declared region={outside}");
			if (csHeader is CsHeader5 && sigType == SigType.Normal && codeHeader.methodDefElemSize == methodDefTable.RowSize) {
				DiagnoseV52Methods(methodInfos);
				DiagnoseV52HeaderMasks(methodInfos);
				DiagnoseV52XorVariants(methodInfos);
				DiagnoseCandidateV52Key(methodInfos);
			}
			csHeader.PatchMethodTable(methodDefTable, methodInfos);

			dumpedMethods = new DumpedMethods();
			decrypter = csHeader.CreateDecrypter();
			if (csHeader is CsHeader5 && sigType == SigType.Normal && codeHeader.methodDefElemSize == methodDefTable.RowSize) {
				byte[] inferredKey = DeriveV52Key(methodInfos);
				if (inferredKey != null && VerifyV52Key(methodInfos, inferredKey)) {
					decrypter = new Decrypter5(peImage, codeHeader, 0x30, inferredKey);
					Logger.n("Agile.NET V52 static decryption: using verified inferred XOR key");
				}
			}
			for (uint rid = 1; rid <= (uint)methodInfos.Count; rid++) {
				var methodInfo = methodInfos[(int)rid - 1];
				if (methodInfo.codeOffs == 0)
					continue;

				var dm = new DumpedMethod();
				peImage.ReadMethodTableRowTo(dm, rid);

				try {
					var mbHeader = decrypter.Decrypt(methodInfo, out dm.code, out dm.extraSections);
					peImage.UpdateMethodHeaderInfo(dm, mbHeader);
				}
				catch (Exception ex) {
					Logger.n($"Agile.NET static decryption: failed at method RID {rid} (token 0x{(0x06000000 + rid):X8}, decrypter {decrypter.GetType().Name})");
					Logger.n($"Agile.NET static decryption: codeOffs=0x{methodInfo.codeOffs:X8}, codeSize={methodInfo.codeSize}, flags=0x{methodInfo.flags:X8}, localVarSigTok=0x{methodInfo.localVarSigTok:X8}");
					Logger.n($"Agile.NET static decryption: {ex.GetType().FullName}: {ex.Message}");
					throw;
				}

				dumpedMethods.Add(dm);
			}
		}

		// Infer a cyclic keystream from V52's redundant fat-header metadata.
		// Reject conflicting or incomplete keys; never use assembly-specific constants.
		byte[] DeriveV52Key(IList<MethodInfo> infos) {
			var key = new byte[16];
			var known = new bool[16];
			uint baseOffset = GetCodeHeaderOffset(peImage);
			int observations = 0;
			for (int i = 0; i < infos.Count; i++) {
				MethodInfo info = infos[i];
				if (info.codeOffs == 0 || info.flags == 0 || info.codeSize < 12 ||
					(ulong)info.codeOffs + info.codeSize > codeHeader.totalCodeSize)
					continue;
				byte[] raw = peImage.OffsetReadBytes(baseOffset + info.codeOffs, 12);
				byte[] expected = new byte[12];
				expected[0] = (byte)info.flags;
				expected[1] = (byte)(info.flags >> 8);
				for (int j = 0; j < 4; j++)
					expected[8 + j] = (byte)(info.localVarSigTok >> (8 * j));
				for (int j = 0; j < 12; j++) {
					if (j >= 2 && j < 8) continue;
					int phase = (int)((info.codeOffs + (uint)j) & 15);
					byte mask = (byte)(raw[j] ^ expected[j]);
					if (known[phase] && key[phase] != mask) {
						Logger.n($"Agile.NET V52 key inference: conflicting mask at phase {phase}");
						return null;
					}
					known[phase] = true;
					key[phase] = mask;
					observations++;
				}
			}
			for (int i = 0; i < known.Length; i++)
				if (!known[i]) {
					Logger.n($"Agile.NET V52 key inference: missing phase {i}");
					return null;
				}
			Logger.n($"Agile.NET V52 key inference: all 16 phases recovered, observations={observations}");
			return key;
		}

		bool VerifyV52Key(IList<MethodInfo> infos, byte[] key) {
			var parser = new Decrypter5(peImage, codeHeader, 0x30, key);
			int verified = 0;
			foreach (MethodInfo info in infos) {
				if (info.codeOffs == 0) continue;
				if (info.codeSize == 0 || info.codeSize > int.MaxValue ||
					(ulong)info.codeOffs + info.codeSize > codeHeader.totalCodeSize) return false;
				try {
					uint fileOffset;
					byte[] data = parser.GetDecryptedBytes(info, out fileOffset);
					uint size, sig;
					ushort flags;
					string reason = ExplainMethodBodyHeader(data, out size, out sig, out flags);
					if (reason != "tiny-structure-ok" && reason != "fat-structure-ok" && reason != "fat-extra-sections")
						return false;
					if ((data[0] & 7) == 3 && (flags != (ushort)info.flags || sig != info.localVarSigTok))
						return false;
					string error;
					if (!parser.TryParseDiagnostic(data, out error)) return false;
					verified++;
				}
				catch (Exception) { return false; }
			}
			Logger.n($"Agile.NET V52 key inference: verified {verified} complete method structures");
			return verified > 0;
		}

		// Mirror the structural checks in MethodBodyParser without changing its behavior.
		static string ExplainMethodBodyHeader(byte[] data, out uint declaredSize, out uint localSig, out ushort headerFlags) {
			declaredSize = 0;
			localSig = 0;
			headerFlags = 0;
			if (data.Length == 0)
				return "empty";
			if ((data[0] & 3) == 2) {
				declaredSize = (uint)(data[0] >> 2);
				return 1UL + declaredSize > (ulong)data.Length ? "tiny-size-overrun" : "tiny-structure-ok";
			}
			if ((data[0] & 7) != 3)
				return "invalid-discriminator";
			if (data.Length < 12)
				return "fat-truncated-header";
			headerFlags = BitConverter.ToUInt16(data, 0);
			declaredSize = BitConverter.ToUInt32(data, 4);
			localSig = BitConverter.ToUInt32(data, 8);
			if ((headerFlags >> 12) != 3)
				return "fat-header-size";
			if (declaredSize > int.MaxValue)
				return "fat-code-size-overflow";
			if (localSig != 0 && (localSig >> 24) != 0x11)
				return "fat-local-sig";
			if (12UL + declaredSize > (ulong)data.Length)
				return "fat-code-overrun";
			return (headerFlags & 8) != 0 ? "fat-extra-sections" : "fat-structure-ok";
		}

		// Compare metadata-derived masks on raw and transformed records; do not modify either.
		void DiagnoseV52HeaderMasks(IList<MethodInfo> methodInfos) {
			const int maxSamples = 512;
			const int maxExamples = 12;
			var candidates = new List<int>();
			for (int i = 0; i < methodInfos.Count; i++) {
				if (methodInfos[i].codeOffs != 0 && methodInfos[i].flags != 0 &&
					methodInfos[i].codeSize >= 12 && (ulong)methodInfos[i].codeOffs + methodInfos[i].codeSize <= codeHeader.totalCodeSize)
					candidates.Add(i);
			}
			if (candidates.Count == 0)
				return;
			var transformedFlagMasks = new Dictionary<ushort, int>();
			var transformedSigMasks = new Dictionary<uint, int>();
			var rawFlagMasks = new Dictionary<ushort, int>();
			var rawSigMasks = new Dictionary<uint, int>();
			int sampled = Math.Min(maxSamples, candidates.Count);
			int errors = 0;
			int examples = 0;
			var diagnosticDecrypter = new Decrypter5(peImage, codeHeader, 0x30);
			for (int i = 0; i < sampled; i++) {
				int index = candidates[(int)((long)i * candidates.Count / sampled)];
				MethodInfo info = methodInfos[index];
				try {
					uint offset;
					byte[] decoded = diagnosticDecrypter.GetDecryptedBytes(info, out offset);
					byte[] raw = peImage.OffsetReadBytes(offset, 12);
					ushort expectedFlags = (ushort)info.flags;
					ushort rawFlagsMask = (ushort)(BitConverter.ToUInt16(raw, 0) ^ expectedFlags);
					ushort decodedFlagsMask = (ushort)(BitConverter.ToUInt16(decoded, 0) ^ expectedFlags);
					uint rawSigMask = BitConverter.ToUInt32(raw, 8) ^ info.localVarSigTok;
					uint decodedSigMask = BitConverter.ToUInt32(decoded, 8) ^ info.localVarSigTok;
					if (!rawFlagMasks.ContainsKey(rawFlagsMask)) rawFlagMasks[rawFlagsMask] = 0;
					rawFlagMasks[rawFlagsMask]++;
					if (!transformedFlagMasks.ContainsKey(decodedFlagsMask)) transformedFlagMasks[decodedFlagsMask] = 0;
					transformedFlagMasks[decodedFlagsMask]++;
					if (!rawSigMasks.ContainsKey(rawSigMask)) rawSigMasks[rawSigMask] = 0;
					rawSigMasks[rawSigMask]++;
					if (!transformedSigMasks.ContainsKey(decodedSigMask)) transformedSigMasks[decodedSigMask] = 0;
					transformedSigMasks[decodedSigMask]++;
					if (examples++ < maxExamples)
						Logger.n($"Agile.NET V52 mask diagnostic: RID {index + 1}, size={info.codeSize}, expectedFlags=0x{expectedFlags:X4}, indexSig=0x{info.localVarSigTok:X8}, raw={BitConverter.ToString(raw)}, transformed={BitConverter.ToString(decoded, 0, 12)}, rawFlagMask=0x{rawFlagsMask:X4}, transformedFlagMask=0x{decodedFlagsMask:X4}, rawSigMask=0x{rawSigMask:X8}, transformedSigMask=0x{decodedSigMask:X8}");
				}
				catch (Exception ex) {
					errors++;
					if (errors <= 4)
						Logger.n($"Agile.NET V52 mask diagnostic: RID {index + 1}, error={ex.GetType().Name}");
				}
			}
			Logger.n($"Agile.NET V52 mask diagnostic: sampled={sampled}, errors={errors}");
			LogTopMasks("raw flags", rawFlagMasks);
			LogTopMasks("transformed flags", transformedFlagMasks);
			LogTopMasks("raw local sig", rawSigMasks);
			LogTopMasks("transformed local sig", transformedSigMasks);
		}

		// Diagnostic only: compare raw, each single-key XOR, and legacy double XOR.
		void DiagnoseV52XorVariants(IList<MethodInfo> methodInfos) {
			const int maxSamples = 512;
			string[] names = { "raw", "key0", "key7", "both" };
			int[] structural = new int[4], parsed = new int[4], flagMatches = new int[4], sigMatches = new int[4];
			int[] attempted = new int[4];
			int errors = 0, logged = 0;
			var indices = new List<int>();
			for (int i = 0; i < methodInfos.Count; i++)
				if (methodInfos[i].codeOffs != 0 && methodInfos[i].flags != 0 &&
					methodInfos[i].codeSize >= 12 && (ulong)methodInfos[i].codeOffs + methodInfos[i].codeSize <= codeHeader.totalCodeSize)
					indices.Add(i);
			var parser = new Decrypter5(peImage, codeHeader, 0x30);
			int count = Math.Min(maxSamples, indices.Count);
			for (int n = 0; n < count; n++) {
				int index = indices[(int)((long)n * indices.Count / count)];
				MethodInfo info = methodInfos[index];
				try {
					uint offset = GetCodeHeaderOffset(peImage) + info.codeOffs;
					byte[] raw = peImage.OffsetReadBytes(offset, (int)info.codeSize);
					for (int variant = 0; variant < 4; variant++) {
						byte[] data = (byte[])raw.Clone();
						for (int j = 0; j < data.Length; j++) {
							int keyIndex = (int)((info.codeOffs - 0x30u + (uint)j) % 16);
							if ((variant & 1) != 0) data[j] ^= codeHeader.decryptionKey[keyIndex];
							if ((variant & 2) != 0) data[j] ^= codeHeader.decryptionKey[(keyIndex + 7) % 16];
						}
						attempted[variant]++;
						uint size, sig;
						ushort flags;
						string reason = ExplainMethodBodyHeader(data, out size, out sig, out flags);
						if (reason == "fat-structure-ok" || reason == "fat-extra-sections") structural[variant]++;
						if (flags == (ushort)info.flags) flagMatches[variant]++;
						if (sig == info.localVarSigTok && (data[0] & 7) == 3 && data.Length >= 12) sigMatches[variant]++;
						string parseError;
						if (parser.TryParseDiagnostic(data, out parseError)) parsed[variant]++;
						if (logged < 16 && variant != 0 && flags == (ushort)info.flags) {
							logged++;
							Logger.n($"Agile.NET V52 XOR diagnostic: RID {index + 1}, variant={names[variant]}, flags=0x{flags:X4}, expectedFlags=0x{info.flags:X4}, sig=0x{sig:X8}, expectedSig=0x{info.localVarSigTok:X8}, declaredSize={size}, recordSize={info.codeSize}, reason={reason}");
						}
					}
				}
				catch (Exception ex) {
					errors++;
					if (errors <= 4) Logger.n($"Agile.NET V52 XOR diagnostic: RID {index + 1}, error={ex.GetType().Name}");
				}
			}
			for (int variant = 0; variant < 4; variant++)
				Logger.n($"Agile.NET V52 XOR diagnostic: variant={names[variant]}, attempted={attempted[variant]}, fatStructure={structural[variant]}, flagMatches={flagMatches[variant]}, sigMatches={sigMatches[variant]}, parseOK={parsed[variant]}, errors={errors}");
		}

		// Candidate derived from known V52 flags and local signature tokens, not used for production decryption.
		static readonly byte[] candidateV52XorKey = {
			0xB4, 0xBE, 0x32, 0x8D, 0x00, 0x81, 0xE3, 0x4D,
			0xC4, 0x59, 0x4A, 0x9E, 0xBC, 0xF7, 0x7C, 0xE4
		};

		void DiagnoseCandidateV52Key(IList<MethodInfo> methodInfos) {
			const int maxFailureExamples = 12;
			int present = 0, parsed = 0, tiny = 0, fat = 0, invalid = 0;
			int fatFlagsMatch = 0, fatSigMatch = 0, failed = 0, errors = 0;
			var reasons = new SortedDictionary<string, int>();
			var parser = new Decrypter5(peImage, codeHeader, 0x30);
			uint bodyBase = GetCodeHeaderOffset(peImage);
			for (int index = 0; index < methodInfos.Count; index++) {
				MethodInfo info = methodInfos[index];
				if (info.codeOffs == 0) continue;
				present++;
				try {
					if (info.codeSize == 0 || info.codeSize > int.MaxValue ||
						(ulong)info.codeOffs + info.codeSize > codeHeader.totalCodeSize)
						throw new InvalidDataException("Invalid record bounds");
					byte[] data = peImage.OffsetReadBytes(bodyBase + info.codeOffs, (int)info.codeSize);
					for (int j = 0; j < data.Length; j++)
						data[j] ^= candidateV52XorKey[(int)((info.codeOffs + (uint)j) & 15)];
					uint declaredSize, sig;
					ushort flags;
					string reason = ExplainMethodBodyHeader(data, out declaredSize, out sig, out flags);
					if (!reasons.ContainsKey(reason)) reasons[reason] = 0;
					reasons[reason]++;
					if (reason == "tiny-structure-ok") tiny++;
					else if (reason == "fat-structure-ok" || reason == "fat-extra-sections") fat++;
					else invalid++;
					if ((data[0] & 7) == 3 && data.Length >= 12) {
						if (flags == (ushort)info.flags) fatFlagsMatch++;
						if (sig == info.localVarSigTok) fatSigMatch++;
					}
					string error;
					if (parser.TryParseDiagnostic(data, out error)) parsed++;
					else if (failed++ < maxFailureExamples)
						Logger.n($"Agile.NET V52 candidate diagnostic: RID {index + 1}, offset=0x{info.codeOffs:X8}, recordSize={info.codeSize}, first=0x{data[0]:X2}, reason={reason}, parse={error}, flags=0x{flags:X4}, indexFlags=0x{info.flags:X8}, sig=0x{sig:X8}, indexSig=0x{info.localVarSigTok:X8}, declaredSize={declaredSize}");
				}
				catch (Exception ex) {
					errors++;
					if (errors <= maxFailureExamples)
						Logger.n($"Agile.NET V52 candidate diagnostic: RID {index + 1}, readError={ex.GetType().Name}");
				}
			}
			Logger.n($"Agile.NET V52 candidate diagnostic: present={present}, parseOK={parsed}, tinyStructureOK={tiny}, fatStructureOK={fat}, invalidStructure={invalid}, fatFlagMatches={fatFlagsMatch}, fatSigMatches={fatSigMatch}, readErrors={errors}");
			foreach (var reason in reasons)
				Logger.n($"Agile.NET V52 candidate diagnostic: structure={reason.Key}, count={reason.Value}");
		}

		static void LogTopMasks<T>(string name, Dictionary<T, int> counts) {
			var entries = new List<KeyValuePair<T, int>>(counts);
			entries.Sort((a, b) => b.Value.CompareTo(a.Value));
			for (int i = 0; i < Math.Min(6, entries.Count); i++)
				Logger.n($"Agile.NET V52 mask diagnostic: {name} mask=0x{Convert.ToUInt64(entries[i].Key):X8}, count={entries[i].Value}");
		}

		// Diagnostic only: does not modify the method table, dump methods, or fallback behavior.
		void DiagnoseV52Methods(IList<MethodInfo> methodInfos) {
			const int maxSamples = 512;
			const int maxFailureLogs = 16;
			var nonempty = new List<int>();
			for (int i = 0; i < methodInfos.Count; i++) {
				if (methodInfos[i].codeOffs != 0)
					nonempty.Add(i);
			}
			if (nonempty.Count == 0)
				return;

			int samples = Math.Min(maxSamples, nonempty.Count);
			int[] testedByFlag = new int[2];
			int[] tinyByFlag = new int[2];
			int[] fatByFlag = new int[2];
			int[] invalidByFlag = new int[2];
			int[] parseOkByFlag = new int[2];
			int[] parseFailedByFlag = new int[2];
			int[] readFailedByFlag = new int[2];
			int failuresLogged = 0;
			int successesLogged = 0;
			var reasons = new SortedDictionary<string, int>();
			int tinyParseOK = 0, fatParseOK = 0, matchingFatLocalSigs = 0, differingFatLocalSigs = 0;
			var diagnosticDecrypter = new Decrypter5(peImage, codeHeader, 0x30);
			Logger.n($"Agile.NET V52 decrypt diagnostic: sampling {samples} of {nonempty.Count} nonempty records (first 16 plus evenly spaced remainder)");
			for (int sample = 0; sample < samples; sample++) {
				int position = sample < 16 ? sample : 16 + (int)((long)(sample - 16) * (nonempty.Count - 16) / Math.Max(1, samples - 16));
				int index = nonempty[position];
				MethodInfo info = methodInfos[index];
				int group = info.flags == 0 ? 0 : 1;
				testedByFlag[group]++;
				string headerKind = "unreadable";
				string parseResult = "not attempted";
				string firstByte = "--";
				string structuralReason = "unreadable";
				uint declaredSize = 0, decodedLocalSig = 0;
				ushort decodedFlags = 0;
				try {
					if (info.codeSize == 0 || (ulong)info.codeOffs + info.codeSize > codeHeader.totalCodeSize)
						throw new InvalidDataException("Record size/range invalid");
					uint fileOffset;
					byte[] data = diagnosticDecrypter.GetDecryptedBytes(info, out fileOffset);
					firstByte = data[0].ToString("X2");
					structuralReason = ExplainMethodBodyHeader(data, out declaredSize, out decodedLocalSig, out decodedFlags);
					if (structuralReason == "fat-structure-ok" || structuralReason == "fat-extra-sections") {
						if (decodedLocalSig == info.localVarSigTok) matchingFatLocalSigs++;
						else differingFatLocalSigs++;
					}
					if ((data[0] & 3) == 2) {
						headerKind = "tiny";
						tinyByFlag[group]++;
					}
					else if ((data[0] & 7) == 3) {
						headerKind = "fat";
						fatByFlag[group]++;
					}
					else {
						headerKind = "invalid";
						invalidByFlag[group]++;
					}
					if (headerKind != "invalid") {
						string error;
						bool valid = diagnosticDecrypter.TryParseDiagnostic(data, out error);
						if (valid) {
							parseOkByFlag[group]++;
							parseResult = "ok";
							if (headerKind == "tiny") tinyParseOK++;
							else fatParseOK++;
						}
						else {
							parseFailedByFlag[group]++;
							parseResult = error;
						}
					}
				}
				catch (Exception ex) {
					readFailedByFlag[group]++;
					parseResult = ex.GetType().Name;
				}
				string category = structuralReason + "/" + parseResult;
				if (!reasons.ContainsKey(category)) reasons[category] = 0;
				reasons[category]++;
				if ((parseResult != "ok" && failuresLogged++ < maxFailureLogs) ||
					(parseResult == "ok" && successesLogged++ < 8))
					Logger.n($"Agile.NET V52 decrypt diagnostic: RID {index + 1}, offset=0x{info.codeOffs:X8}, size={info.codeSize}, flags=0x{info.flags:X8}, indexSig=0x{info.localVarSigTok:X8}, first=0x{firstByte}, header={headerKind}, decodedFlags=0x{decodedFlags:X4}, decodedSize={declaredSize}, decodedSig=0x{decodedLocalSig:X8}, reason={structuralReason}, parse={parseResult}");
			}
			for (int group = 0; group < 2; group++)
				Logger.n($"Agile.NET V52 decrypt diagnostic: flags {(group == 0 ? "zero" : "nonzero")}: tested={testedByFlag[group]}, tiny={tinyByFlag[group]}, fat={fatByFlag[group]}, invalid={invalidByFlag[group]}, parseOK={parseOkByFlag[group]}, parseFailed={parseFailedByFlag[group]}, readFailed={readFailedByFlag[group]}");
			Logger.n($"Agile.NET V52 decrypt diagnostic: parseOK tiny={tinyParseOK}, fat={fatParseOK}; structurally valid fat local signatures matching index={matchingFatLocalSigs}, differing={differingFatLocalSigs}");
			foreach (var reason in reasons)
				Logger.n($"Agile.NET V52 decrypt diagnostic: outcome {reason.Key}: {reason.Value}");
		}

		void ReadCodeHeader(uint offset) {
			codeHeader.signature = peImage.OffsetReadBytes(offset, 16);
			codeHeader.decryptionKey = peImage.OffsetReadBytes(offset + 0x10, 16);
			codeHeader.totalCodeSize = peImage.OffsetReadUInt32(offset + 0x20);
			codeHeader.numMethods = peImage.OffsetReadUInt32(offset + 0x24);
			codeHeader.methodDefTableOffset = peImage.OffsetReadUInt32(offset + 0x28);
			codeHeader.methodDefElemSize = peImage.OffsetReadUInt32(offset + 0x2C);
		}

		static SigType GetSigType(byte[] sig) {
			if (Utils.Compare(sig, normalSignature))
				return SigType.Normal;
			else if (Utils.Compare(sig, proSignature))
				return SigType.Pro;
			else if (Utils.Compare(sig, oldSignature))
				return SigType.Old;
			return SigType.Unknown;
		}

		static bool IsValidSignature(byte[] signature) => GetSigType(signature) != SigType.Unknown;

		public static bool Detect(MyPEImage peImage) {
			try {
				uint codeHeaderOffset = GetCodeHeaderOffset(peImage);
				if (IsValidSignature(peImage.OffsetReadBytes(codeHeaderOffset, 16)))
					return true;
			}
			catch {
			}

			try {
				uint codeHeaderOffset = GetOldCodeHeaderOffset(peImage);
				if (codeHeaderOffset != 0 && IsValidSignature(peImage.OffsetReadBytes(codeHeaderOffset, 16)))
					return true;
			}
			catch {
			}

			return false;
		}
	}
}
