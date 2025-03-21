# Contributing to **libbpf-rs**

### Anyone is welcome to make **libbpf-rs** better!

Thank you for wanting to contribute to **libbpf-rs**. We are delighted to have you.

**libbpf-rs** is an open source project and we love receiving contributions from the
community! There are many ways to contribute, such as improving the
documentation, submitting bug reports and feature requests, reviewing code,
answering questions on pull requests, and submitting code that can be merged into
**libbpf-rs** itself.

## Code of Conduct

**libbpf-rs** adopts and adheres to the Linux [Code of
Conduct](https://www.kernel.org/doc/html/latest/process/code-of-conduct.html).

## Triaging Issues and Pull Requests

One great way you can contribute to the project without writing any code is to
help triage issues and pull requests as they come in.

- Ask for more information if you believe the issue does not provide all the
  details required to solve it.
- Flag issues that are stale or that should be closed.
- Review code.

## Submitting a Pull Request

Here are some suggested guidelines for a smooth experience:

- **Pull requests should be against `master`.**
All pull requests should be opened against the `master` branch.

- **Keep your commits small.**
If your changes are big (~300+ lines of diff), please break them down into
smaller commits. Smaller commits are much easier to review and more likely
to get merged in. Please make sure each commit is an isolated change (eg if
the commit does 2 separate things, please split it).

- **Maintain a fully working commit history.**
Each commit should represent a fully working state, i.e., not be breaking builds
or causing test failures. Doing so helps when bisecting issues in the future.

- **Use a descriptive title.**

- **Include useful details in the commit messages.**
Providing context helps reviewers understand the change and helps expedite
feedback. Please provide a detailed enough description of (high-level) what
the change does and why it is needed.

- **Squash commits that address feedback.**
Follow-up changes to the submitted commit should be amended to the commit,
not pushed out as a separate commit.

- **Document `unsafe` blocks.**
Please make sure that each `unsafe` block your code requires is accompanied by a
`SAFETY` comment. Similar for `unsafe` functions. These comments should state
why required invariants are upheld at the callsite or what invariants exist,
respectively. Please refer to the [Standard Library Developer's
Guide](https://std-dev-guide.rust-lang.org/policy/safety-comments.html).

- **Accompany your code with tests.**
Please make an effort to add regression tests for bug fixes and unit or
integration tests for newly added functionality.

- **Add a CHANGELOG note.**
If your change is user facing or otherwise notable, it should likely be
mentioned in the respective `CHANGELOG.md` files of the crates being
touched.

- **Run rustfmt before submitting.**.
Running rustfmt (`cargo fmt`) will help fix any styling inconsistencies.
It is checked by CI, but running rustfmt before submitting will help reduce
churn for your pull request.
