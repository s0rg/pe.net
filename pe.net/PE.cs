using System;
using System.Text;
using System.Collections.Generic;

using System.IO;
using System.Runtime.InteropServices;

namespace pe.net
{
	public class PE : IDisposable
	{
        #region Simplified PE Object representation

		public struct Import
		{
			public string Module;
			public string Name;
			public UInt16 Ordinal;
		}

		public struct Export
		{
			public string Module;
			public string Forwarded;
			public string Name;
			public UInt16 Ordinal;
		}

		public struct Section
		{
			public string Name;
			public UInt32 VirtualSize;
			public UInt32 VirtualAddress;
			public UInt32 SizeOfRawData;
			public UInt32 PointerToRawData;
			public DataSectionFlags Characteristics;
		}

        #endregion
		
		#region Static Methods
		public static PE fromFile(string path)
		{
			PE pe = null;
			
			try {
				pe = new PE(new FileStream(path, FileMode.Open));
			} catch {
			}
			
			return pe;
		}
		
		public static string ResolveOrdinalName(string module, UInt16 ordinal)
		{
			string name = String.Empty;
			
			PE pe = PE.fromFile(module);
			if (pe != null) {
				pe.LoadExports();
				if (pe.Exports.ContainsKey(ordinal))
					name = pe.Exports[ordinal];
				pe.Dispose();
			}
			return name;
		}
		#endregion
		
		internal delegate bool ImportThunkReader(out UInt32 offset,out UInt16 ordinal);
		
		private BinaryReaderEx pe;

		/// <summary>
		/// The DOS header
		/// </summary>
		private IMAGE_DOS_HEADER dosHeader;

		/// <summary>
		/// The file header
		/// </summary>
		private IMAGE_FILE_HEADER fileHeader;

		/// <summary>
		/// Optional 32 bit file header
		/// </summary>
		private IMAGE_OPTIONAL_HEADER32 optionalHeader32;

		/// <summary>
		/// Optional 64 bit file header
		/// </summary>
		private IMAGE_OPTIONAL_HEADER64 optionalHeader64;

		/// <summary>
		/// Image Section headers. Number of sections is in the file header.
		/// </summary>
		private IMAGE_SECTION_HEADER[] imageSectionHeaders;
		private Dictionary<string, Section> _sections = null;
		private Dictionary<string, List<Import>> _imports = new Dictionary<string, List<Import>>();
		private Dictionary<UInt16, string> _exports = new Dictionary<UInt16, string>();
		private PeType peType;

        #region Properties

		/// <summary>
		/// Gets if the file header is 32 bit or not
		/// </summary>
		public bool Is32BitHeader {
			get {
				return (this.peType != PeType.PE64);
			}
		}
		
		/// <summary>
		/// Gets the type of the image.
		/// </summary>
		/// <value>
		/// The type of the image.
		/// </value>
		public PeType ImageType {
			get {
				return peType;
			}
		}

		/// <summary>
		/// Gets the file header
		/// </summary>
		public IMAGE_FILE_HEADER FileHeader {
			get {
				return fileHeader;
			}
		}
		
		/// <summary>
		/// Gets the entry point.
		/// </summary>
		/// <value>
		/// The entry point.
		/// </value>
		public UInt32 EntryPoint {
			get {
				if (this.Is32BitHeader)
					return optionalHeader32.AddressOfEntryPoint;
				else
					return optionalHeader64.AddressOfEntryPoint;
			}
		}
		
		/// <summary>
		/// Gets the sections.
		/// </summary>
		/// <value>
		/// The sections.
		/// </value>
		public Dictionary<string, Section> Sections {
			get {
				return _sections;
			}
		}
		
		/// <summary>
		/// Gets the imports.
		/// </summary>
		/// <value>
		/// The imports.
		/// </value>
		public Dictionary<string, List<Import>> Imports {
			get {
				return _imports;
			}
		}
		
		/// <summary>
		/// Gets the exports.
		/// </summary>
		/// <value>
		/// The exports.
		/// </value>
		public Dictionary<UInt16, string> Exports {
			get {
				return _exports;
			}
		}

		/// <summary>
		/// Gets the optional header
		/// </summary>
		public IMAGE_OPTIONAL_HEADER32 OptionalHeader32 {
			get {
				return optionalHeader32;
			}
		}

		/// <summary>
		/// Gets the optional header
		/// </summary>
		public IMAGE_OPTIONAL_HEADER64 OptionalHeader64 {
			get {
				return optionalHeader64;
			}
		}
		
		/// <summary>
		/// Gets the image section headers.
		/// </summary>
		/// <value>
		/// The image section headers.
		/// </value>
		public IMAGE_SECTION_HEADER[] ImageSectionHeaders {
			get {
				return imageSectionHeaders;
			}
		}

		/// <summary>
		/// Gets the timestamp from the file header
		/// </summary>
		public DateTime TimeStamp {
			get {
				// Timestamp is a date offset from 1970
				DateTime returnValue = new DateTime(1970, 1, 1, 0, 0, 0);

				// Add in the number of seconds since 1970/1/1
				returnValue = returnValue.AddSeconds(fileHeader.TimeDateStamp);
				// Adjust to local timezone
				returnValue += TimeZone.CurrentTimeZone.GetUtcOffset(returnValue);

				return returnValue;
			}
		}

        #endregion Properties

		/// <summary>
		/// Create new PE Object from strean
		/// </summary>
		/// <param name="stream"></param>
		public PE(Stream stream, bool load_full = false)
		{
			pe = new BinaryReaderEx(stream);
			
			try {
				pe.ReadStruct<IMAGE_DOS_HEADER>(out this.dosHeader);

				if (dosHeader.e_magic != 0x5A4D) // MZ
					throw new Exception("Invalid DOS header");

				pe.Seek(dosHeader.e_lfanew);

				UInt32 nt_sign = pe.ReadUInt32();

				if (nt_sign != 0x4550) // PE
					throw new Exception("Invalid PE signature");

				pe.ReadStruct<IMAGE_FILE_HEADER>(out fileHeader);

				ushort magic = pe.ReadUInt16();
				pe.Seek(-2, SeekOrigin.Current);
				
				switch (magic) {
					case (ushort)PeType.PE32:
						this.peType = PeType.PE32;
						pe.ReadStruct<IMAGE_OPTIONAL_HEADER32>(out this.optionalHeader32);
						break;

					case (ushort)PeType.PE64:
						this.peType = PeType.PE64;
						pe.ReadStruct<IMAGE_OPTIONAL_HEADER64>(out this.optionalHeader64);
						break;

					case (ushort)PeType.ROM:
						this.peType = PeType.ROM;
						break;

					default:
						throw new Exception("Invalid IMAGE_FILE_HEADER.Magic value");
				}
				
				if (this.peType != PeType.ROM) {
					this.imageSectionHeaders = pe.ReadStructArray<IMAGE_SECTION_HEADER>(fileHeader.NumberOfSections);
					
					this.loadSections();
					
					if (load_full)
						this.LoadFull();
				}
			
			} catch (Exception e) {
				pe = null;
				throw e;
			}
		}

		/// <summary>
		/// Load sections
		/// </summary>
		private void loadSections()
		{
			_sections = new Dictionary<string, Section>(fileHeader.NumberOfSections);
			foreach (var sec in imageSectionHeaders) {
				var section = new Section
                {
					Name = sec.Name.TrimEnd(new char[] {'\0'}),
					VirtualSize = sec.VirtualSize,
					VirtualAddress = sec.VirtualAddress,
					SizeOfRawData = sec.SizeOfRawData,
					PointerToRawData = sec.PointerToRawData,
					Characteristics = sec.Characteristics
                };
				_sections[section.Name] = section;
			}
		}

		private bool readImportThunk32(out UInt32 offset, out UInt16 ordinal)
		{
			UInt32 thunk = pe.ReadUInt32();

			ordinal = UInt16.MinValue;
			offset = UInt32.MinValue;

			if (thunk == 0) {
				return false;
			}

			if ((thunk & 0x80000000) != 0) {
				ordinal = Convert.ToUInt16(thunk & 0x7FFF);
			} else {
				offset = thunk;
			}

			return true;
		}

		private bool readImportThunk64(out UInt32 offset, out UInt16 ordinal)
		{
			ulong thunk = pe.ReadUInt64();

			ordinal = UInt16.MinValue;
			offset = UInt32.MinValue;

			if (thunk == 0) {
				return false;
			}

			if ((thunk & 0x8000000000000000) != 0) {
				ordinal = Convert.ToUInt16(thunk & 0x7FFF);
			} else {
				offset = Convert.ToUInt32(thunk);
			}

			return true;
		}

		/// <summary>
		/// Load imports
		/// </summary>
		public void LoadImports()
		{
			UInt32 chunk_rva;
			UInt16 ordinal;
			string curr_module, funk_name;

			IMAGE_DATA_DIRECTORY import;
			IMAGE_IMPORT_DESCRIPTOR descriptor;
			ImportThunkReader thunk_reader;
			
			if (this.Is32BitHeader) {
				import = optionalHeader32.ImportTable;
				thunk_reader = new ImportThunkReader(this.readImportThunk32);
			} else {
				import = optionalHeader64.ImportTable;
				thunk_reader = new ImportThunkReader(this.readImportThunk64);
			}

			int iid_size = Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));

			for (long offset = Rva2Offset(import.VirtualAddress);; offset += iid_size) {
				pe.Seek(offset);
				pe.ReadStruct<IMAGE_IMPORT_DESCRIPTOR>(out descriptor);

				if (descriptor.Name == 0)
					break;

				curr_module = pe.ReadAsciiZ(Rva2Offset(descriptor.Name)).ToLower();

				if (!_imports.ContainsKey(curr_module))
					_imports.Add(curr_module, new List<Import>());

				long iat_offset = (descriptor.TimeDateStamp != 0 && descriptor.OriginalFirstThunk != 0)
                                   ? Rva2Offset(descriptor.OriginalFirstThunk)
                                   : Rva2Offset(descriptor.FirstThunk);

				pe.Seek(iat_offset);
				
				while (thunk_reader.Invoke(out chunk_rva, out ordinal)) {
					funk_name = String.Empty;
					
					if (ordinal == UInt16.MinValue) {
						iat_offset = pe.Tell;

						long rva = Rva2Offset(chunk_rva);
						if (rva < 0)
							throw new Exception("RVA in thunk points outside of image!");

						pe.Seek(rva);
						ordinal = pe.ReadUInt16();
						funk_name = pe.ReadAsciiZ();

						pe.Seek(iat_offset);
					}

					_imports[curr_module].Add(new Import() {
                        Module = curr_module,
                        Name = funk_name,
                        Ordinal = ordinal
                    });
				}
			}
		}

		public void LoadRelocations()
		{
			//TODO: Write some code
		}

		/// <summary>
		/// Load Export table
		/// </summary>
		public void LoadExports()
		{
			//TODO: Add forwarded export processing
			
			IMAGE_DATA_DIRECTORY export;
			UInt32 rva;
			string name;

			if (this.Is32BitHeader)
				export = optionalHeader32.ExportTable;
			else
				export = optionalHeader64.ExportTable;

			IMAGE_EXPORT_DIRECTORY export_dir;

			if (export.VirtualAddress == 0)
				return;

			pe.Seek(Rva2Offset(export.VirtualAddress));
			pe.ReadStruct<IMAGE_EXPORT_DIRECTORY>(out export_dir);

			long name_offset = Rva2Offset(export_dir.AddressOfNames);
			long ord_offset = Rva2Offset(export_dir.AddressOfNameOrdinals);

			for (int i = 0; i < export_dir.NumberOfNames; i++) {
				//read ENT entry
				pe.Seek(name_offset);
				rva = pe.ReadUInt32();
				name_offset = pe.Tell;

				//read name
				name = pe.ReadAsciiZ(Rva2Offset(rva));

				// read EOT entry
				pe.Seek(ord_offset);
				UInt16 ord = pe.ReadUInt16();
				ord_offset = pe.Tell;

				_exports.Add(ord, name);
			}
		}

		/// <summary>
		/// Load full (Relocs/Imports/Exports)
		/// </summary>
		public void LoadFull()
		{
			LoadRelocations();
			LoadImports();
			LoadExports();
		}
		
		/// <summary>
		/// Reads the section raw data
		/// </summary>
		/// <returns>
		/// Section raw data
		/// </returns>
		/// <param name='section'>
		/// Section.
		/// </param>
		public byte[] ReadSectionRaw(Section section)
		{
			pe.Seek(section.PointerToRawData);
			
			return pe.ReadBytes((int)section.SizeOfRawData);
		}
		/*
		public void Save(Stream stream)
		{

		}

		public void Rebase(UInt32 newBaseAddress)
		{

		}

		public void SectionAdd(Section section)
		{

		}

		public void SectionDel(Section section)
		{

		}
		*/
		public long Rva2Offset(UInt32 rva)
		{
			uint sec_size;

			foreach (IMAGE_SECTION_HEADER sec in imageSectionHeaders) {
				if (rva >= sec.VirtualAddress) {
					sec_size = sec.VirtualAddress + sec.VirtualSize;

					if (rva < sec_size)
						return (rva - sec.VirtualAddress + sec.PointerToRawData);
				}
			}

			return 0L;
		}

		public void Dispose()
		{
			if (pe != null)
				pe.Close();
		}
	}
}

