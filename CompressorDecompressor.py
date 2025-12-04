import os

import zstandard as zstd


class CompressorDecompressor:
    def __init__(self, chunk_size: int = 16 * 1024 * 1024):
        """
        Initialize compressor/decompressor.

        Args:
            chunk_size: Size of chunks for streaming operations (default 4MB)
        """
        self.CHUNK = chunk_size

    @staticmethod
    def compress_file(infile: str) -> str:
        """
        Compress file efficiently for any size.
        Works with both small (KB) and large (GB+) files.
        Writes compressed data directly to a temp file.

        Args:
            infile: Path to input file

        Returns:
            Path to the temporary file containing compressed data
        """
        print("Compressing file...")

        import tempfile

        compressor = zstd.ZstdCompressor(
            level=1,
            threads=-1,
            write_content_size=True
        )

        # Create temp file for compressed data
        temp_fd, temp_filepath = tempfile.mkstemp(dir='/tmp', suffix='.zst')
        # temp_fd, temp_filepath = tempfile.mkstemp(dir='/var/tmp', suffix='.zst')
        try:
            with open(infile, 'rb') as fin:
                with os.fdopen(temp_fd, 'wb') as temp_file:
                    # Stream compress directly from input file to temp file
                    compressor.copy_stream(fin, temp_file)

            print(f"Compressed data stored at: {temp_filepath}")
            return temp_filepath

        except Exception as e:
            # Clean up temp file on error
            if os.path.exists(temp_filepath):
                os.unlink(temp_filepath)
            raise ValueError(f"Compression failed: {str(e)}")

    @staticmethod
    def decompress_data(infile: str, outfile: str):
        """
        Decompress data from input file directly into output file.

        Args:
            infile: Path to the compressed input file
            outfile: Path to the output file for decompressed data

        Returns:
            None
        """
        print("Decompressing data...")
        decompressor = zstd.ZstdDecompressor()

        with open(infile, 'rb') as fin:
            with open(outfile, 'wb') as fout:
                # Use copy_stream for efficient streaming decompression
                decompressor.copy_stream(fin, fout)

        print(f"Data decompressed to: {outfile}")
