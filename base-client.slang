defcall postIdSet(?ServerJVM, ?ServerPrincipal, ?Envs, ?CN) :-
  {
    postIdSet($ServerJVM, $ServerPrincipal, $Envs, $CN).
  }.

defcall postSubjectSet(?ServerJVM, ?ServerPrincipal, ?Envs) :-
  {
    postSubjectSet($ServerJVM, $ServerPrincipal, $Envs).
  }.

defcall updateSubjectSet(?ServerJVM, ?ServerPrincipal, ?Envs, ?Token) :-
  {
    updateSubjectSet($ServerJVM, $ServerPrincipal, $Envs, $Token).
  }.

defcall passDelegation(?ServerJVM, ?ServerPrincipal, ?Envs, ?Token, ?Scid) :-
  {
    passDelegation($ServerJVM, $ServerPrincipal, $Envs, $Token, $Scid).
  }.
