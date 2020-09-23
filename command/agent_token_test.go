package command

import (
	"fmt"
	"os"
	"testing"

	"github.com/mitchellh/cli"
)

func testAgentTokenCommand(tb testing.TB) (*cli.MockUi, *AgentTokenCommand) {
	tb.Helper()

	ui := cli.NewMockUi()
	return ui, &AgentTokenCommand{
		BaseCommand: &BaseCommand{
			UI: ui,
		},
	}
}

func expectEqual(t *testing.T, actual, expected string) {
	if actual != expected {
		t.Errorf("Expect `%s` to equal `%s`", actual, expected)
	}
}

func TestAgentToken_Run_MissingInput(t *testing.T) {
	ui, cmd := testAgentTokenCommand(t)

	code := cmd.Run([]string{"-config", "xyz"})
	if code != 1 {
		t.Errorf("Agent token command should be 1: %d", code)
	}
	expected := "Must specify the input text using -input\n"
	expectEqual(t, ui.ErrorWriter.String(), expected)
}

func TestAgentToken_Run_MissingConfig(t *testing.T) {
	ui, cmd := testAgentTokenCommand(t)

	code := cmd.Run([]string{""})
	if code != 1 {
		t.Errorf("Agent token command should be 1: %d", code)
	}
	expected := "Must specify exactly one config path using -config\n"
	expectEqual(t, ui.ErrorWriter.String(), expected)
}

func TestAgentToken_Run_MissingTokenConfig(t *testing.T) {
	config := fmt.Sprintf(`
vault {
   address = "http://127.0.0.1:8200"
}
`)
	configPath := makeTempFile(t, "config.hcl", config)
	defer os.Remove(configPath)

	ui, cmd := testAgentTokenCommand(t)

	code := cmd.Run([]string{"-config", configPath, "-input", "hello"})
	if code != 1 {
		t.Errorf("Agent token command should be 1: %d", code)
	}
	expected := "'TokenConfig' is missing in the configuration file\n"
	expectEqual(t, ui.ErrorWriter.String(), expected)
}

func TestAgentToken_Run_MissingTokenConfigSecret(t *testing.T) {
	config := fmt.Sprintf(`
token_config {
}
`)
	configPath := makeTempFile(t, "config.hcl", config)
	defer os.Remove(configPath)

	ui, cmd := testAgentTokenCommand(t)

	code := cmd.Run([]string{"-config", configPath, "-input", "hello"})
	if code != 1 {
		t.Errorf("Agent token command should be 1: %d", code)
	}
	expected := "'TokenConfig => secret' is missing in the configuration file\n"
	expectEqual(t, ui.ErrorWriter.String(), expected)
}

func TestAgentToken_Run(t *testing.T) {
	config := fmt.Sprintf(`
token_config {
	secret = "testme"
}
`)
	configPath := makeTempFile(t, "config.hcl", config)
	defer os.Remove(configPath)

	ui, cmd := testAgentTokenCommand(t)
	code := cmd.Run([]string{"-config", configPath, "-input", "hello"})
	if code != 0 {
		t.Errorf("Agent token command should be 0: %d", code)
	}
	expected := "c97df02ad05c0c2e36e9a14ae90fd9d4de0d419e7dd4ed8ef3edb1c8fa1ca914\n"
	expectEqual(t, ui.OutputWriter.String(), expected)

	ui, cmd = testAgentTokenCommand(t)
	code = cmd.Run([]string{"-config", configPath, "-input", "hello2"})
	if code != 0 {
		t.Errorf("Agent token command should be 0: %d", code)
	}
	expected = "8e3a983397b780b3f265b7c9af91ec4b5919cac922ea9b35a174231546a26b96\n"
	expectEqual(t, ui.OutputWriter.String(), expected)

	//Token value should be consistent against the same input and secret
	ui, cmd = testAgentTokenCommand(t)
	code = cmd.Run([]string{"-config", configPath, "-input", "hello"})
	if code != 0 {
		t.Errorf("Agent token command should be 0: %d", code)
	}
	expected = "c97df02ad05c0c2e36e9a14ae90fd9d4de0d419e7dd4ed8ef3edb1c8fa1ca914\n"
	expectEqual(t, ui.OutputWriter.String(), expected)

	config = fmt.Sprintf(`
token_config {
	secret = "testme2"
}
`)
	configPath2 := makeTempFile(t, "config2.hcl", config)
	defer os.Remove(configPath2)

	ui, cmd = testAgentTokenCommand(t)
	code = cmd.Run([]string{"-config", configPath2, "-input", "hello"})
	if code != 0 {
		t.Errorf("Agent token command should be 0: %d", code)
	}
	expected = "6c17d4115fecbbe7c8cbe81f63aa14ee0aca802b9c1dd84f250febd22a5141ac\n"
	expectEqual(t, ui.OutputWriter.String(), expected)

	ui, cmd = testAgentTokenCommand(t)
	code = cmd.Run([]string{"-config", configPath, "-input", "hello2"})
	if code != 0 {
		t.Errorf("Agent token command should be 0: %d", code)
	}
	expected = "8e3a983397b780b3f265b7c9af91ec4b5919cac922ea9b35a174231546a26b96\n"
	expectEqual(t, ui.OutputWriter.String(), expected)

	//Token value should be consistent against the same input and secret
	ui, cmd = testAgentTokenCommand(t)
	code = cmd.Run([]string{"-config", configPath2, "-input", "hello"})
	if code != 0 {
		t.Errorf("Agent token command should be 0: %d", code)
	}
	expected = "6c17d4115fecbbe7c8cbe81f63aa14ee0aca802b9c1dd84f250febd22a5141ac\n"
	expectEqual(t, ui.OutputWriter.String(), expected)
}
