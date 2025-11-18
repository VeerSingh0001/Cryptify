import zstandard as zstd


class CompressorDecompressor:

    @staticmethod
    def compress_file(infile):
        print("Compressing file...")
        compressor = zstd.ZstdCompressor(level=5, threads=-1)
        compobj = compressor.compressobj()
        result = b""
        with open(infile, 'rb') as fh:
            while True:
                chunk = fh.read(4 * 1024 * 1024)
                if not chunk:
                    break
                result += compobj.compress(chunk)
            result += compobj.flush()
        return result

    @staticmethod
    def compress_data(data):
        print("Compressing data...")
        compressor = zstd.ZstdCompressor(level=7, threads=-1)
        compobj = compressor.compressobj()
        result = compobj.compress(data)
        result += compobj.flush()
        return result

    @staticmethod
    def decompress_data(data):
        print("Decompressing data...")
        decompressor = zstd.ZstdDecompressor()
        compobj = decompressor.decompressobj()
        result = compobj.decompress(data)
        result += compobj.flush()
        return result
