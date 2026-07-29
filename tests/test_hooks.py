"""Framework adapters.

The adapters are tested against stand-ins that mimic each framework's shape
rather than against the frameworks themselves, so the suite stays runnable
without installing five agent stacks. What is being tested is the wrapping
logic: that the tool's callable is replaced, that the replacement enforces,
and that anything unrecognised is refused instead of quietly left open.
"""

from __future__ import annotations

import sys

import pytest
from conftest import boot

from hlyn.hooks import SPOTS, attach, wrap

REAL = sys.platform in ("linux", "darwin")
here = pytest.mark.skipif(not REAL, reason="no enforcement backend on this platform")


# ---------------------------------------------------------------------------
# stand-ins
# ---------------------------------------------------------------------------


class Tool:
    """A LangChain/LlamaIndex-shaped tool: the callable lives on an attribute."""

    def __init__(self, fn, spot="func"):
        setattr(self, spot, fn)
        self.name = "probe"


class Agent:
    """Anything that holds a list of tools."""

    def __init__(self, tools):
        self.tools = tools


class Crew:
    def __init__(self, agents):
        self.agents = agents


class Bot:
    """AutoGen-shaped: a name-to-callable mapping."""

    def __init__(self, table):
        self.function_map = table


class Ship:
    """Swarm-shaped: plain callables in a list."""

    def __init__(self, functions):
        self.functions = functions


# ---------------------------------------------------------------------------
# the wrapping itself
# ---------------------------------------------------------------------------


def test_wrap_keeps_the_name_and_docstring():
    def search(q):
        """Find things."""
        return q

    got = wrap(search)
    assert got.__name__ == "search"
    assert got.__doc__ == "Find things."


def test_attach_replaces_the_callable_on_each_spot():
    for spot in ("func", "_run", "run", "fn"):
        target = Tool(lambda: 1, spot=spot)
        before = getattr(target, spot)
        attach(target)
        assert getattr(target, spot) is not before, f"{spot} was not wrapped"


def test_attach_walks_a_list():
    tools = [Tool(lambda: 1), Tool(lambda: 2)]
    before = [t.func for t in tools]
    attach(tools)
    assert [t.func for t in tools] != before


def test_attach_refuses_something_that_is_not_a_tool():
    with pytest.raises(TypeError) as caught:
        attach(object())
    assert "does not look like a tool" in str(caught.value)


def test_attach_names_the_attributes_it_looked_for():
    with pytest.raises(TypeError) as caught:
        attach(object())
    for spot in SPOTS[:3]:
        assert spot in str(caught.value)


def test_every_adapter_exposes_attach():
    from hlyn.hooks import autogen, crewai, langchain, llamaindex, swarm

    for mod in (langchain, crewai, autogen, llamaindex, swarm):
        assert callable(mod.attach), f"{mod.__name__} has no attach"


def test_langchain_adapter_walks_tools():
    from hlyn.hooks import langchain

    agent = Agent([Tool(lambda: 1)])
    before = agent.tools[0].func
    langchain.attach(agent)
    assert agent.tools[0].func is not before


def test_crewai_adapter_walks_agents():
    from hlyn.hooks import crewai

    crew = Crew([Agent([Tool(lambda: 1)])])
    before = crew.agents[0].tools[0].func
    crewai.attach(crew)
    assert crew.agents[0].tools[0].func is not before


def test_autogen_adapter_walks_the_function_map():
    from hlyn.hooks import autogen

    bot = Bot({"search": lambda: 1})
    before = bot.function_map["search"]
    autogen.attach(bot)
    assert bot.function_map["search"] is not before


def test_swarm_adapter_walks_functions():
    from hlyn.hooks import swarm

    ship = Ship([lambda: 1])
    before = ship.functions[0]
    swarm.attach(ship)
    assert ship.functions[0] is not before


# ---------------------------------------------------------------------------
# does it actually confine
# ---------------------------------------------------------------------------


@here
def test_a_wrapped_tool_returns_its_result():
    done = boot(
        """
        from hlyn.hooks import wrap
        assert wrap(lambda: 6 * 7)() == 42
        print("RESULT OK")
        """
    )
    assert done.returncode == 0, done.stderr
    assert "RESULT OK" in done.stdout


@here
def test_a_wrapped_tool_cannot_reach_what_the_policy_denies():
    done = boot(
        """
        from hlyn.hooks import wrap
        def peek():
            return open("/etc/hosts").read()
        try:
            wrap(peek)()
        except Exception:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """
    )
    assert done.returncode == 0, f"a confined tool read outside its boundary: {done.stdout}"


@here
def test_the_caller_is_not_confined_by_wrapping_a_tool():
    # The point of per-tool confinement: the agent process keeps its own
    # permissions, and only the tool call is narrowed.
    done = boot(
        """
        import hlyn
        from hlyn.hooks import wrap
        wrap(lambda: 1)()
        assert not hlyn.sealed(), "wrapping a tool confined the caller"
        open("/etc/hosts").read()
        print("CALLER FREE")
        """
    )
    assert done.returncode == 0, done.stderr
    assert "CALLER FREE" in done.stdout


@here
def test_the_decorator_confines_too():
    done = boot(
        """
        from hlyn.hooks import tool

        @tool(net=False)
        def peek():
            return open("/etc/hosts").read()

        try:
            peek()
        except Exception:
            print("REFUSED"); raise SystemExit(0)
        print("ESCAPED"); raise SystemExit(1)
        """
    )
    assert done.returncode == 0, f"the decorated tool escaped: {done.stdout}"


@here
def test_a_tool_may_be_granted_what_the_agent_lacks(tmp_path):
    (tmp_path / "data.txt").write_text("visible")
    done = boot(
        f"""
        from hlyn.hooks import wrap
        got = wrap(lambda: open({str(tmp_path / 'data.txt')!r}).read(), read=[{str(tmp_path)!r}])()
        print(got)
        """
    )
    assert done.returncode == 0, done.stderr
    assert "visible" in done.stdout
