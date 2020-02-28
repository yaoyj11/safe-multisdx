//defenv Selfie() :-
//  spec("Load the principal keypair"),
//  principal($1).

defenv Version() :- "set200".
defenv PolicyVersion() :- "policy200".

defenv MyAnchorSet() :- anchorSet().

//
// Identity set (apply to all participants)
//

defcon makeMyIdentitySet(?CN) :-
  spec("Construct the identity set for self"),
  {
    principal($SelfKey) :- spec("identity set for $CN").
  }.

defcon makeMySubjectSet() :-
  spec("Construct the subject set for self"),
  {
    link($Self).
    label("subject($Self)($Version)").
  }.

defcon makeCapabilitySet(?Token, ?Scid) :-
  spec("Construct a capability set for ?Scid"),
  {
    link($Token).
    label("capability($Scid)($Version)").
  }.

defcon addTokenToSubjectSet(?Token) :-
  spec("Add a token to the user's subject set. Invoke after the user gets a delegation"),
  {
    link($Token).
    label("subject($Self)($Version)").
  }.

defpost updateSubjectSet(?Token) :- [addTokenToSubjectSet(?Token)].

defpost postIdSet(?CN) :- [makeMyIdentitySet(?CN)].

defpost postSubjectSet() :- [makeMySubjectSet()].

defpost passDelegation(?Token, ?Scid) :-
  ?CapSetRef := label($Self, "capability(?Scid)($Version)"),
  [makeCapabilitySet(?Token, ?Scid), addTokenToSubjectSet(?CapSetRef)].


