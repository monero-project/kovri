# Contributing
- The Kovri I2P Router Project welcomes all contributions.
- Every pull request and correspondence will be treated with the utmost respect and consideration.
- Don't forget: this is *your* Kovri too!

## IRC
Join us in ```#kovri-dev``` on Irc2P or Freenode; we'll be happy to say hi!

## Style
We ardently adhere to (or are in the process of adhering to) [Google's C++ Style Guide](https://google.github.io/styleguide/cppguide.html).

Please run [cpplint](https://github.com/google/styleguide/tree/gh-pages/cpplint) on any applicable work before contributing to Kovri.

In addition to the aforementioned, please consider the following:

- If function args newline break, ensure that *every* indent is 4 spaces (and not 2).

```cpp
if (clearText[BUILD_REQUEST_RECORD_FLAG_OFFSET] & 0x40) {
  // So, we send it to reply tunnel
  i2p::transport::transports.SendMessage(
      clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
      ToSharedI2NPMessage(
          CreateTunnelGatewayMsg(
              bufbe32toh(
                  clearText + BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
              e_I2NPVariableTunnelBuildReply,
              buf,
              len,
              bufbe32toh(
                  clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET))));
} else {
  i2p::transport::transports.SendMessage(
      clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
      ToSharedI2NPMessage(
          CreateI2NPMessage(
              e_I2NPVariableTunnelBuild,
              buf,
              len,
              bufbe32toh(
                  clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET))));
}
```

- Pointers: reference/dereference operators on the left (attached to datatype) when possible.
- Abstain from datatype declaration redundancy (e.g., use commas instead of repeating the datatype).

```cpp
uint32_t tunnelID,
         nextTunnelID;

uint8_t layerKey[32],
        ivKey[32],
        replyKey[32],
        replyIV[16],
        randPad[29];

bool isGateway,
     isEndpoint;
```

- Class member variables are prepended with m_
- Enumerators are prepended with e_

## TODO's
Do a quick search in the codebase for TODO(unassigned) and/or pick a ticket and start patching!

## Workflow
To contribute a patch, consider the following:

- Fork Kovri
- Create a topic branch
- Commit your feature(s)/patch(es)
- Pull request to branch ```development```

In general, commits should be [atomic](https://en.wikipedia.org/wiki/Atomic_commit#Atomic_commit_convention) and diffs should be easy to read. For this reason, please try to not mix formatting fixes with non-formatting commits.

Commit messages should be verbose by default, consisting of a short subject line (50 chars max), a blank line, and detailed explanatory text as separate paragraph(s) - unless the title alone is self-explanatory.

If a particular commit references another issue, please add a reference. For example "See #123", or "Fixes #123". This will help us resolve tickets when we merge into ```master```.

The body of the pull request should contain an accurate description of what the patch does and provide justification/reasoning for the patch (when appropriate). You should include references to any discussions such as other tickets or chats on IRC.

## Bounty
In the future we will provide bounty for vulnerabilities and bugs. Please stay tuned while we work out the details.

## Model
We do our best to adhere to the [Agile](https://en.wikipedia.org/wiki/Agile_development)/[Scrum](https://en.wikipedia.org/wiki/Scrum_%28development%29) software development model. The benefits of such a model will become more apparent when our software and developer-base grows (we hope!). Please, consider this model before contributing.

## Conflict resolution 
```
2015-11-30 18:37:36 &anonimal   Ok, so let's determine a pecking order re: conflict resolution:
2015-11-30 18:37:40 &anonimal   Scenario:
2015-11-30 18:38:18 &anonimal   1. Contributor has an idea and it should be master
2015-11-30 18:38:38 &anonimal   2. 'lead dev' disagrees with idea, wants their own version of idea in master
2015-11-30 18:39:11 &anonimal   3. Monero likes contributor's idea, but lead dev has more experience with the code.
2015-11-30 18:39:16 ~fluffypon  ok so this is something that we *have* established in Monero
2015-11-30 18:39:16 &anonimal   What is the solution?
2015-11-30 18:39:44 ~fluffypon  we basically open decisions up to the community, and try get so-called "rough consensus"
2015-11-30 18:40:23 ~fluffypon  there are plenty of savvy community members who aren't direct contributors to the codebase, so opening it up for discussion is good
2015-11-30 18:40:45 ~fluffypon  if it is truly contentious and there's no general community consensus then we escalate it
2015-11-30 18:41:05 ~fluffypon  basically the Monero Core Team have an online meeting
2015-11-30 18:41:08 ~fluffypon  which is closed to outside participants, but publicly visible 
2015-11-30 18:41:19 ~fluffypon  and we discuss the options, and then vote on it
2015-11-30 18:41:26 &anonimal   Is there a timelimit to gather this consensus? How long should devs wait for results?
2015-11-30 18:41:55 ~fluffypon  every core team member has the option of a veto vote, else they must vote no, yes but I can't support the effort, yes and I can support the effort, yes and I can drive the effort
2015-11-30 18:42:09 ~fluffypon  anonimal: it depends on the urgency of the situation
2015-11-30 18:42:15 ~fluffypon  a nice-to-have feature might require a month of discussion
2015-11-30 18:42:25 ~fluffypon  an urgent, but controversial, change might require a week
2015-11-30 18:42:54 &anonimal   Ok, great to know. Thanks for clarifying.
```
