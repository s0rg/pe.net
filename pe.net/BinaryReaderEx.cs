using System;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;

namespace pe.net
{
	public class BinaryReaderEx : BinaryReader
	{
		public BinaryReaderEx(Stream stream)
            : base(stream)
		{
		}

		/// <summary>
		/// Return current stream position
		/// </summary>
		public long Tell {
			get {
				return BaseStream.Position;
			}
		}
		/// <summary>
		/// Read structure from current position
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="result"></param>
		public void ReadStruct<T>(out T result)
               where T : struct
		{
			int count = Marshal.SizeOf(typeof(T));
			byte[] buffer = ReadBytes(count);

			GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
			result = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
			handle.Free();
		}

		/// <summary>
		/// Read array of structs from current position
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="count"></param>
		/// <returns></returns>
		public T[] ReadStructArray<T>(int count)
               where T : struct
		{
			var result = new T[count];
			int size = Marshal.SizeOf(typeof(T));
			var buffer = new byte[size];

			GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);

			for (int i = 0; i < count; i++) {
				BaseStream.Read(buffer, 0, size);
				result[i] = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
			}

			handle.Free();

			return result;
		}

		/// <summary>
		/// Seek replacement
		/// </summary>
		/// <param name="offset"></param>
		/// <param name="from"></param>
		/// <returns></returns>
		public long Seek(long offset, SeekOrigin from = SeekOrigin.Begin)
		{
			return BaseStream.Seek(offset, from);
		}

		/// <summary>
		/// Read AsciiZ string from position (from current if omitted)
		/// </summary>
		/// <param name="offset"></param>
		/// <param name="from"></param>
		/// <returns></returns>
		public String ReadAsciiZ(long offset = 0, SeekOrigin from = SeekOrigin.Begin)
		{
			StringBuilder sb = new StringBuilder();
			int b = 0;

			if (offset != 0)
				BaseStream.Seek(offset, from);
			
			do {
				b = BaseStream.ReadByte();
				if (b == 0)
					break;
				sb.Append(Convert.ToChar(b));
			} while ( true );

			return sb.ToString();
		}
	}
}

