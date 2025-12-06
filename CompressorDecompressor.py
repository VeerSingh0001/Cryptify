import os
import tempfile

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

    def compress_file(self, infile: str) -> str:
        """
        Compress file efficiently for any size.
        Writes compressed data directly to a temp file.

        Args:
            infile: Path to input file

        Returns:
            Path to the temporary file containing compressed data
        """
        print("Compressing file...")

        compressor = zstd.ZstdCompressor(
            level=1,
            threads=-1,
            write_content_size=True
        )

        # Create temp file for compressed data
        temp_fd, temp_filepath = tempfile.mkstemp(dir='/var/tmp', suffix='.zst')
        try:
            with open(infile, 'rb', buffering=self.READ_SIZE) as fin:
                with os.fdopen(temp_fd, 'wb', buffering=self.WRITE_SIZE) as temp_file:
                    # Stream compress directly from input file to temp file
                    compressor.copy_stream(fin, temp_file, read_size=self.READ_SIZE, write_size=self.WRITE_SIZE)
            print(f"Compressed data stored at: {temp_filepath}")
            return temp_filepath

        except Exception as e:
            # Clean up temp file on error
            if os.path.exists(temp_filepath):
                os.unlink(temp_filepath)
            raise ValueError(f"Compression failed: {str(e)}")

    def decompress_data(self, infile: str, outfile: str):
        """
        Decompress data from input file directly into output file.

        Args:
            infile: Path to the compressed input file
            outfile: Path to the output file for decompressed data

        Returns:
            None
        """
        print("Decompressing data...")
        decompressor = zstd.ZstdDecompressor(max_window_size=2 ** 31)
        try:
            with open(infile, 'rb', buffering=self.READ_SIZE) as fin:
                with open(outfile, 'wb', buffering=self.WRITE_SIZE) as fout:
                    # Use copy_stream for efficient streaming decompression
                    decompressor.copy_stream(fin, fout, read_size=self.READ_SIZE, write_size=self.WRITE_SIZE)
        except Exception as e:
            print(f"Decompression failed: {str(e)}")
            raise

        print(f"Data decompressed to: {outfile}")
