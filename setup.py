from setuptools import setup


def readme():
    with open('README.md') as f:
        return f.read()


setup(name='frida_rpc',
      version='0.1.2',
      description='Expose frida RPC as a service you can access over the web or network',

      long_description=readme(),
      long_description_content_type='text/markdown',
      classifiers=[

          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3.6',
      ],
      keywords='frida rpc web network internet reverse engineering',
      url='https://github.com/ydaniels/frida-web-rpc',
      author='Yomi D',
      author_email='yomid4all@gmail.com',
      license='MIT',
      packages=['frida_rpc'],
      include_package_data=True,
      install_requires=[
          'flask',
          'frida'
      ],
      zip_safe=False)
