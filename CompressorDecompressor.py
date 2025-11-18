import zstandard as zstd


class CompressorDecompressor:
    def __init__(self):
        self.plaintext = b""
        self.compressed_data = b""

    def compress_file(self, infile):
        print("Compressing file...")
        compressor = zstd.ZstdCompressor(level=5, threads=-1)
        compobj = compressor.compressobj()
        with open(infile, 'rb') as infile:
            while True:
                chunk = infile.read(4 * 1024 * 1024)
                if not chunk:
                    break
                compressed_chunk = compobj.compress(chunk)
                self.plaintext += compressed_chunk
            tail = compobj.flush()
            self.plaintext += tail

            return self.plaintext

    def compress_data(self, data):
        print("Compressing data...")
        compressor = zstd.ZstdCompressor(level=7, threads=-1)
        compobj = compressor.compressobj()
        self.compressed_data += compobj.compress(data)
        tail = compobj.flush()
        self.compressed_data += tail
        return self.compressed_data
