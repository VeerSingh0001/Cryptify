import zstandard as zstd


class CompressorDecompressor:
    def __init__(self, chunk_size: int = 4 * 1024 * 1024):
        """
        Initialize compressor/decompressor.
        
        Args:
            chunk_size: Size of chunks for streaming operations (default 4MB)
        """
        self.CHUNK = chunk_size

    def compress_file(self, infile):
        """
        Compress file with efficient streaming to memory.
        Uses bytearray for better allocation strategy than repeated string concatenation.
        
        Args:
            infile: Path to input file
            
        Returns:
            Compressed data as bytes
        """
        print("Compressing file...")
        compressor = zstd.ZstdCompressor(level=5, threads=-1)
        compobj = compressor.compressobj()
        result = bytearray()
        
        with open(infile, 'rb') as fh:
            while True:
                chunk = fh.read(self.CHUNK)
                if not chunk:
                    break
                # Extend bytearray instead of bytes concatenation
                result.extend(compobj.compress(chunk))
        
        result.extend(compobj.flush())
        return bytes(result)

    @staticmethod
    def compress_data(data):
        """
        Compress data in-memory with optimized level for speed.
        
        Args:
            data: Data to compress (bytes)
            
        Returns:
            Compressed data as bytes
        """
        print("Compressing data...")
        compressor = zstd.ZstdCompressor(level=7, threads=-1)
        compobj = compressor.compressobj()
        result = bytearray()
        result.extend(compobj.compress(data))
        result.extend(compobj.flush())
        return bytes(result)

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
        compobj = decompressor.decompressobj()
        result = bytearray()
        result.extend(compobj.decompress(data))
        result.extend(compobj.flush())
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
        compobj = decompressor.decompressobj()

        with open(outfile, "wb") as f:
            offset = 0
            total = len(data)

            while offset < total:
                chunk = data[offset: offset + self.CHUNK]
                offset += self.CHUNK

                out = compobj.decompress(chunk)
                if out:
                    f.write(out)

            tail = compobj.flush()
            if tail:
                f.write(tail)

