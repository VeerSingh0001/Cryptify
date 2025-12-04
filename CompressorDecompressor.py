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
    def compress_file(infile):
        """
        Compress file efficiently for any size.
        Works with both small (KB) and large (GB+) files.

        Args:
            infile: Path to input file

        Returns:
            Compressed data as bytes
        """
        print("Compressing file...")

        compressor = zstd.ZstdCompressor(
            level=1,
            threads=-1,
            write_content_size=True
        )

        from io import BytesIO
        output = BytesIO()

        with open(infile, 'rb') as fh:
            compressor.copy_stream(fh, output)

        return output.getvalue()

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

    # @staticmethod
    # def decompress_data(data):
    #     """
    #     Decompress data in-memory.
    #
    #     Args:
    #         data: Compressed data (bytes)
    #
    #     Returns:
    #         Decompressed data as bytes
    #     """
    #     print("Decompressing data...")
    #     decompressor = zstd.ZstdDecompressor()
    #
    #     from io import BytesIO
    #
    #     # Wrap input data in BytesIO for streaming
    #     input_stream = BytesIO(data)
    #     output = BytesIO()
    #
    #     # Use copy_stream for efficient decompression
    #     decompressor.copy_stream(input_stream, output)
    #
    #     return output.getvalue()
