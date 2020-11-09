from setuptools import setup, find_packages

setup(
    name="win64-debugger",
    version="0.0.1",
    python_requires=">=3.6",
    author="David Foster",
    author_email="foster.dev999@gmail.com",
    description="A Windows 64-bit proccess debugger",
    license="MIT",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "win64-debugger = win64_debugger:cli",
            "w64-db = win64_debugger:cli",
        ]
    },
)
