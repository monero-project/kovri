# Quality Assurance

The following is a proposed model for QA workflow. While linear in nature, any phase can be worked on individually if needed - as long as all phases are eventually addressed.

## Phase 1: Basic Review

- All code must adhere to our contributing guidelines
- Note areas that need improving (mentally or in code)
- Create TODO's and assign if possible

## Phase 2: Specification Review /  Implementation / Code Documentation

- Complete specification review on a per module basis; e.g., Streaming, I2PControl, etc.
  - Code must be in-line with essential parts of the specification that will maintain the same (or better) level of anonymity that java I2P provides
  - Refactor/implement/patch when/where needed
- Ensure C++14 compliant implementation
  - Review phase 2 if needed
- Resolve all related TODO's
- Document code as much as possible with inline comments and Doxygen
  - Code should be understood by novice to experienced coders
  - Code should guide the reader to a better understanding of I2P
    - I2P is very complex so our code should act as sovereign replacement of spec documentation and not simply as a supplement (this can be a tedious objective but very rewarding in terms of maintenance and software lifespan)

## Phase 3: Crypto Review / Security auditing

- Ensure that crypto is up-to-date and properly implemented
- Establish every vector for known exploitation
  - Keep these vectors in mind when writing tests
- Break Kovri every which-way possible
  - Fix what you break
- Always use trustworthy, well-written libraries when possible
  - Avoid homebrewed, ad-hoc, *I'm sure I know better than the community* type of code
- Seek a 2nd (or more) opinion(s) from colleagues before proceeding to next phase

## Phase 4: Bug squashing / Tests / Profiling

- Resolve priority bugs/issues
- Write unit-tests tests for every module
  - Run tests. Run them again
  - Full review of test results. Patch if needed. Refactor as necessary
- Ensure that automation is running on a regular basis
  - valgrind, doxygen, clang-format
  - Patch if needed, refactor as necessary

## Phase 5: Confer

- Confer with colleagues and the community
  - Conferring should be done publicly via ticket, meetings, and/or IRC
- Accept all feedback and, in response, produce tangible results
- If satisfied, proceed with next phase, else repeat this phase (or start from a previous phase)

## Phase 6: Repeat the cycle from the beginning
