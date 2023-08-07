# This test attempts to run the script sd-jwt-generate from the command line to see if the script runs without errors.
# Note: The script must be run from the "examples" directory.

import subprocess


def test_generate_py():
    # Run the script
    result = subprocess.run(
        ["sd-jwt-generate", "example"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="examples",
    )

    # Check that the script ran without errors
    assert result.returncode == 0
    assert result.stderr == b""


# Same as above, but run in "testcase" mode from "testcases" directory
def test_generate_py_testcase():
    # Run the script
    result = subprocess.run(
        ["sd-jwt-generate", "testcase"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="tests/testcases",
    )

    # Check that the script ran without errors
    assert result.returncode == 0
    assert result.stderr == b""
