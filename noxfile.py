import nox


@nox.session(venv_backend="none")
def fmt(s: nox.Session) -> None:
    s.run("ruff", "check", ".", "--select", "I", "--fix")
    s.run("black", ".")


@nox.session(venv_backend="none")
def fmt_check(s: nox.Session) -> None:
    s.run("ruff", "check", ".", "--select", "I")
    s.run("black", "--check", ".")


@nox.session(venv_backend="none")
def lint(s: nox.Session) -> None:
    s.run("ruff", "check", ".", "--fix")


@nox.session(venv_backend="none")
def lint_check(s: nox.Session) -> None:
    s.run("ruff", "check", ".")


@nox.session(venv_backend="none")
def type_check(s: nox.Session) -> None:
    s.run("mypy", "src")


@nox.session(venv_backend="none")
def test(s: nox.Session) -> None:
    s.run("pytest", "-v", "--cov", "-s")
    s.run("coverage", "report")
    s.run("coverage", "xml")
