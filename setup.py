from setuptools import setup

setup(
    name = "apkbleach",
    version = "2.1",
    author = "graylagx2",
    author_email = "graylagx2@gmail.com",
    description = ("Payload obfuscation and icon injection"),
    url = "https://github.com/graylagx2/apkbleach",
    packages=['apkbleach'],
    package_dir={'apkbleach': 'src'},
    package_data={'apkbleach': ['res/*']},
    install_requires=[
        'argparse',
        'colorama',
        'pillow',
        'pyfiglet==0.8.post1',
        'requests',
    ],
    entry_points = {
        'console_scripts': ['apkbleach = src.apkbleach.__main__:main']
    }
)