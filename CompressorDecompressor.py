import os
import tempfile
import appdirs

import zstandard as zstd


class CompressorDecompressor:
    def __init__(self, chunk_size: int = 16 * 1024 * 1024):
        """
        Initialize compressor/decompressor.

        Args:
            chunk_size: Size of chunks for streaming operations (default 4MB)
        """
        self.CHUNK = chunk_size
        self.READ_SIZE = 256 * 1024
        self.WRITE_SIZE = 4 * 1024 * 1024
        self.app_name = "Cryptify"
        self.app_author = "User"
        self.temp_dir = appdirs.user_cache_dir(self.app_name, self.app_author)

    @staticmethod
    def compress_file(data) :
        """

        Args:
            data: chunk data

        Returns:
            Compressed chunked data
        """

        compressor = zstd.ZstdCompressor(
            level=1,
            threads=-1,
            write_content_size=True
        )
        return compressor.compress(data)


    @staticmethod
    def decompress_data(data):
        """
        Decompress data from input file directly into output file.

        Args:
            data: decrypted chunk data

        Returns:
            decompressed chunk data
        """
        decompressor = zstd.ZstdDecompressor(max_window_size=2 ** 31)
        return decompressor.decompress(data)
