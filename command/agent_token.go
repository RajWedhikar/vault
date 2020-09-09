package command

import (
	"fmt"
	"strings"

	agentConfig "github.com/hashicorp/vault/command/agent/config"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*AgentTokenCommand)(nil)

type AgentTokenCommand struct {
	*BaseCommand

	flagConfigs []string
	input       string
}

func (c *AgentTokenCommand) Synopsis() string {
	return "Generate a Vault agent token based on the -input text"
}

func (c *AgentTokenCommand) Help() string {
	helpText := `
Usage: vault agent token [options]

  This command generates a token based on the input text.

  Run the command with an input text and a configuration file:

      $ vault agent token -input xxxx -config=/etc/vault/config.hcl

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *AgentTokenCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)

	f := set.NewFlagSet("Command Options")

	f.StringSliceVar(&StringSliceVar{
		Name:   "config",
		Target: &c.flagConfigs,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
		),
		Usage: "Path to a configuration file. This configuration file should " +
			"contain only agent directives.",
	})

	f.StringVar(&StringVar{
		Name:   "input",
		Target: &c.input,
		Usage:  "The input text will be used to generate a token",
	})

	return set
}

func (c *AgentTokenCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Validation
	if len(c.flagConfigs) != 1 {
		c.UI.Error("Must specify exactly one config path using -config")
		return 1
	}

	if c.input == "" {
		c.UI.Error("Must specify the input text using -input")
		return 1
	}

	// Load the configuration
	config, err := agentConfig.LoadConfig(c.flagConfigs[0])
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error loading configuration from %s: %s", c.flagConfigs[0], err))
		return 1
	}

	// Ensure at least one config was found.
	if config == nil {
		c.UI.Error("Failed to load config file. Please provide the configuration with the -config flag.")
		return 1
	}

	if config.TokenConfig == nil {
		c.UI.Error("'TokenConfig' is missing in the configuration file")
		return 1
	}

	if config.TokenConfig.Secret == "" {
		c.UI.Error("'TokenConfig => secret' is missing in the configuration file")
		return 1
	}

	c.UI.Output(agentConfig.IdentityToken(config.TokenConfig.Secret, c.input))

	return 0
}
