import zstandard as zstd


class CompressorDecompressor:
    def __init__(self, chunk_size: int = 1 * 1024 * 1024):
        """
        Initialize compressor/decompressor.
        
        Args:
            chunk_size: Size of chunks for streaming operations (default 4MB)
        """
        self.CHUNK = chunk_size
        self.compressor = zstd.ZstdCompressor(level=1, threads=-1)
        self.decompressor = zstd.ZstdDecompressor()
        self.compobj = self.compressor.compressobj()
        self.decompobj = self.decompressor.decompressobj()

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

        result = bytearray()
        
        with open(infile, 'rb') as fh:
            while True:
                chunk = fh.read(self.CHUNK)
                if not chunk:
                    break
                # Extend bytearray instead of bytes concatenation
                result.extend(self.compobj.compress(chunk))
        
        result.extend(self.compobj.flush())
        return bytes(result)

    def compress_data(self,data):
        """
        Compress data in-memory with optimized level for speed.
        
        Args:
            data: Data to compress (bytes)
            
        Returns:
            Compressed data as bytes
        """
        print("Compressing data...")
        result = bytearray()
        result.extend(self.compobj.compress(data))
        result.extend(self.compobj.flush())
        return bytes(result)

    def decompress_data(self,data):
        """
        Decompress data in-memory.
        
        Args:
            data: Compressed data (bytes)
            
        Returns:
            Decompressed data as bytes
        """
        print("Decompressing data...")

        result = bytearray()
        result.extend(self.decompobj.decompress(data))
        result.extend(self.decompobj.flush())
        return bytes(result)

    def decompress_data_to_file(self, data, outfile):
        """
        Decompress data to file with streaming to avoid high memory usage.
        
        Args:
            data: Compressed data (bytes)
            outfile: Path to output file
        """
        print("Decompressing data to file...")

        with open(outfile, "wb") as f:
            offset = 0
            total = len(data)

            while offset < total:
                chunk = data[offset: offset + self.CHUNK]
                offset += self.CHUNK

                out = self.decompobj.decompress(chunk)
                if out:
                    f.write(out)

            tail = self.decompobj.flush()
            if tail:
                f.write(tail)

