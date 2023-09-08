# OSS Checker

This script checks for vulnerabilities using the OSS index. It now supports Maven, Conda, and Python directory structures, and can process multiple structure types in a single run.

## Setup

1. Clone the repository.
2. Install the necessary packages by running: `pip install -r requirements.txt`.

## Usage

1. In the `main.py` file, you will find the script to check vulnerabilities.
2. Run the script using the command: `python main.py`.
3. You will be prompted to enter the directory path where your packages are located.
4. Next, you will be asked to specify the structure types (maven, conda, or python) based on the packages you want to check. You can specify multiple types separated by commas.
   - For Maven structure, the script will process the directory as it did previously.
   - For Conda structure, specify 'conda'. The script will then process `.conda` files in the directory and extract package names and versions.
   - For Python structure, specify 'python'. The script will process files in the directory to extract package names and versions, saving the output to a text file in the same directory.
5. Follow the remaining prompts to complete the vulnerability check.
6. The vulnerabilities are written to a file named "vulnerabilities.xlsx".

## Example

For Maven and Conda:
- Directory Path: `/home/ubuntu/Downloads/<directory>`
- Structure Types: `maven,conda`

For Python and Conda:
- Directory Path: `/home/ubuntu/Downloads/<directory>`
- Structure Types: `python,conda`

## Note

- For Python structure, the output will also be saved to a text file named "python_output.txt" in the specified directory.
- Ensure that the directory paths and structure types are entered correctly to get accurate results.


