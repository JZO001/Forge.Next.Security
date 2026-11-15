description: Creating a commit message for the actual changes of the current branch than do the commit into the current branch

Write me a description of what I changed in the current solution code. This text is for a "git commit". Do not include any information about the AI ​​or its creator in the commit text.

Put the text into a new git commit and execute it. Do not push the commit into the repository.

Before doing the commit, always run the tests from the folder "tests". If something is failing, do not commit and report the issue.

Skip the tests when nothing but the knowledge base changed since the last commit: `AGENTS.md`, `CLAUDE.md`, the `AI/` documents, other Markdown files, and the instruction and prompt files under `.claude/` and `.github/`. Say in the report that the tests were skipped, and why. A change to anything else - source, tests, project, configuration or build files - gets the test run.

If you have any questions, ask!
