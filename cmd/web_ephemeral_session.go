package cmd

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"

	webcli "github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/web"
)

func wrapEphemeralSessionCommands(root *ffcli.Command) {
	mode := root.FlagSet.Lookup("experimental-web-session").Value.(flag.Getter)
	var wrap func(*ffcli.Command, string)
	wrap = func(command *ffcli.Command, path string) {
		for _, child := range command.Subcommands {
			wrap(child, path+" "+child.Name)
		}
		if command.Exec == nil {
			return
		}
		exec := command.Exec
		command.Exec = func(ctx context.Context, args []string) error {
			if mode.Get().(bool) {
				var err error
				ctx, err = webcli.ContextWithEphemeralSession(ctx, path, command.FlagSet)
				if err != nil {
					return err
				}
			}
			return exec(ctx, args)
		}
	}
	for _, command := range root.Subcommands {
		wrap(command, root.Name+" "+command.Name)
	}
}
