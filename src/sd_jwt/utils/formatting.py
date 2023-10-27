import json
import logging
from textwrap import fill, wrap
from pathlib import Path

from sd_jwt.common import SDObj

logger = logging.getLogger("sd_jwt")

OUTPUT_INDENT = 2
EXAMPLE_MAX_WIDTH = 68
EXAMPLE_SHORT_WIDTH = 60
OUTPUT_ENSURE_ASCII = False

#######################################################################
# Helper functions to format examples
#######################################################################


def textwrap_json(data, width=EXAMPLE_MAX_WIDTH):
    text = json.dumps(data, indent=OUTPUT_INDENT, ensure_ascii=OUTPUT_ENSURE_ASCII)
    output = []
    for line in text.splitlines():
        if len(line) <= width:
            output.append(line)
        else:
            # Check if line is of the form "key": "value"
            if not line.strip().startswith('"'):
                logger.warning("unexpected line " + line)
                output.append(line)
                continue
            # Determine number of spaces before the value
            ##spaces = line.index(":") + 2
            spaces = line.index('"') + OUTPUT_INDENT
            # Wrap the value
            wrapped = wrap(
                line[spaces:],
                width=width - spaces,
                break_on_hyphens=False,
                replace_whitespace=False,
            )
            # Add the wrapped value to the output
            output.append(line[:spaces] + wrapped[0])
            for line in wrapped[1:]:
                output.append(" " * spaces + line)
    output = "\n".join(text for text in output)

    return output


def textwrap_text(text, width=EXAMPLE_MAX_WIDTH):
    return fill(
        text,
        width=width,
        break_on_hyphens=False,
    )


def multiline_code(text):
    # Add a ` character to each start and end of a line and a backslash after each line
    return "\\\n".join(f"`{line}`" for line in text.splitlines())


def markdown_disclosures(disclosures):
    markdown = ""
    for d in disclosures:
        if d.key is None:
            markdown += f"__Array Entry__:\n\n"
        else:
            markdown += f"__Claim `{d.key}`__:\n\n"

        markdown += (
            f" * SHA-256 Hash: `{d.hash}`\n"
            f" * Disclosure:\\\n"
            f"{multiline_code(textwrap_text(d.b64, EXAMPLE_SHORT_WIDTH))}\n"
            f" * Contents:\n"
            f"{multiline_code(textwrap_text(d.json, EXAMPLE_SHORT_WIDTH))}\n\n\n"
        )

    return markdown.strip()


def markdown_decoy_digests(decoy_digests):
    # create a list of decoy digests in markdown format
    return "\n".join(f" * `{digest}`" for digest in decoy_digests)


def format_for_testcase(data, ftype):
    if ftype == "json":
        return json.dumps(data, indent=OUTPUT_INDENT, ensure_ascii=OUTPUT_ENSURE_ASCII)
    else:
        return data


def format_for_example(data, ftype):
    if ftype == "json":
        if isinstance(data, str):
            data = json.loads(data)
        return textwrap_json(data)
    elif ftype == "txt":
        return textwrap_text(data)
    else:
        return data
