import zstandard as zstd


class CompressorDecompressor:
    def __init__(self):
        self.CHUNK = 4 * 1024 * 1024

    def compress_file(self, infile):
        print("Compressing file...")
        compressor = zstd.ZstdCompressor(level=5, threads=-1)
        compobj = compressor.compressobj()
        result = b""
        with open(infile, 'rb') as fh:
            while True:
                chunk = fh.read(self.CHUNK)
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

    def decompress_data_to_file(self, data, outfile):
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
