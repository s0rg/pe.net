using System;
using System.Collections.Generic;

using pe.net;

namespace libtest
{
	class MainClass
	{
		public static void Main(string[] args)
		{
			if (args.Length != 1) {
				Console.WriteLine("usage: libtest pe-file");
				return;
			}

			PE pe = PE.fromFile(args[0]);
			
			if (pe == null) {
				Console.WriteLine("Malformed or non-PE file: {0}", args[0]);
				return;
			}
			
			Console.WriteLine("File: {0}", args[0]);
			Console.WriteLine("Type: {0}", pe.ImageType);

			foreach (KeyValuePair<String, PE.Section> S in pe.Sections) {
				Console.WriteLine("Section: {0} Address: {1:X} Size: {2:X}",
				                  S.Key, S.Value.VirtualAddress, S.Value.SizeOfRawData);
				Console.WriteLine("\tCharacteristics: {0}", S.Value.Characteristics);
			}

			pe.LoadImports();

			foreach (var entry in pe.Imports) {
				Console.WriteLine("imports from [{0}]", entry.Key);

				foreach (var import in entry.Value) {
					if (import.Name == String.Empty)
						Console.WriteLine("\tby ordinal: {0}", import.Ordinal);
					else
						Console.WriteLine("\tby name: {0} ord: {1}", import.Name, import.Ordinal);
				}
			}

			pe.LoadExports();

			Console.WriteLine("Exports: ");

			foreach (var export in pe.Exports) {
				Console.WriteLine("\tOrdinal: {0} Name: {1}", export.Key, export.Value);
			}
			
			pe.Dispose();
		}
	}
}
