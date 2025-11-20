import os
import zstandard as zstd


class CompressorDecompressor:
    def __init__(self, chunk_size: int = 1 * 1024 * 1024):
        """
        Initialize compressor/decompressor.
        
        Args:
            chunk_size: Size of chunks for streaming operations (default 4MB)
        """
        self.CHUNK = chunk_size


    def compress_file(self, infile,temp):
        """
        Compress file with efficient streaming to memory.
        Uses bytearray for better allocation strategy than repeated string concatenation.
        
        Args:
            infile: Path to input file
            temp: Path to temp directory

        Returns:
            Compressed data as bytes
        """
        print("Compressing file...")
        compressor = zstd.ZstdCompressor(level=1, threads=-1)
        compobj = compressor.compressobj()

        filename = os.path.basename(infile)

        with open(infile, 'rb') as src, open(f"{temp}/{filename}", "wb") as dst:
            while True:
                chunk = src.read(self.CHUNK)
                if not chunk:
                    break

                out = compobj.compress(chunk)
                if out:
                    dst.write(out)

            tail = compobj.flush()
            if tail:
                dst.write(tail)

    @staticmethod
    def decompress_data(data):
        """
        Decompress data in-memory.
        
        Args:
            data: Compressed data (bytes)
            
        Returns:
            Decompressed data as bytes
        """
        print("Decompressing data...")

        decompressor = zstd.ZstdDecompressor()
        decompobj = decompressor.decompressobj()
        result = bytearray()
        result.extend(decompobj.decompress(data))
        result.extend(decompobj.flush())
        return bytes(result)

    def decompress_data_to_file(self, data, outfile):
        """
        Decompress data to file with streaming to avoid high memory usage.
        
        Args:
            data: Compressed data (bytes)
            outfile: Path to output file
        """
        print("Decompressing data to file...")
        decompressor = zstd.ZstdDecompressor()
        decompobj = decompressor.decompressobj()
        with open(outfile, "wb") as f:
            offset = 0
            total = len(data)

            while offset < total:
                chunk = data[offset: offset + self.CHUNK]
                offset += self.CHUNK

                out = decompobj.decompress(chunk)
                if out:
                    f.write(out)

            tail = decompobj.flush()
            if tail:
                f.write(tail)

