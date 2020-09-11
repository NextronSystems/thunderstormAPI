import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="thunderstormAPI",
    version="0.1.0",
    author="Florian Roth",
    author_email="florian.roth@nextron-systems.com",
    description="THOR Thunderstorm Service API Client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/NextronSystems/thunderstormAPI",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'packaging',
        'requests',
        'configparser',
    ],
    python_requires='~=3.5',
    entry_points={
        'console_scripts': [
            'thunderstorm-cli = thunderstormAPI.thunderstorm_cli:main',
        ],
    },
)
