import setuptools
 
with open("README.md", "r") as fh:
    long_description = fh.read()
 
setuptools.setup(
    name="aws_consoler",
    version="1.1.0",
    author="Ian Williams",
    author_email="ian.williams@netspi.com",
    description="A utility to convert your AWS CLI credentials into AWS "
                "console access.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.8',
    ],
    python_requires='>=3.8',
)