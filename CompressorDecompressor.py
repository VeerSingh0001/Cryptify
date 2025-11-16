import  zstandard as zstd

class CompressorDecompressor:
    def __init__(self):
        self.plaintext = b""


    def compress_file(self,infile):
        compressor = zstd.ZstdCompressor(level=5, threads=-1)
        compobj = compressor.compressobj()
        with open(infile, 'rb') as infile:
            while True:
                chunk = infile.read(4 * 1024 * 1024)
                if not chunk:
                    break
                compressed_chunk = compobj.compress(chunk)
                # print("Comp Chunks",compressed_chunk)
                self.plaintext += compressed_chunk
                # print(chunk)
            tail = compobj.flush()
            self.plaintext += tail

            return self.plaintext

    @staticmethod
    def compress_data(data):
        compressor = zstd.ZstdCompressor(level=5, threads=-1)
        compobj = compressor.compressobj()
        compressed_data = compobj.compress(data)
        return compressed_data


