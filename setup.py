from setuptools import setup, find_packages

setup(
    name="apkspider",
    version="0.1.0",
    description="Automated APK Extraction & Analysis Tool",
    long_description="""
    APKSpider is an automated tool for extracting and analyzing APK and XAPK files.
    It allows users to download, decompile, and analyze APK files.
    The tool supports multiple platforms and is designed to work seamlessly across operating systems (Windows, macOS, Linux).
    """,
    long_description_content_type="text/markdown",
    author="s0undsystem",
    url="https://github.com/s0undsystem/apkspider",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests",
        "python-magic",
    ],
    entry_points={
        "console_scripts": [
            "apkspider=apkspider.main:main",
        ],
    },
)
