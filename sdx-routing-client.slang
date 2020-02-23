import('../stitch-all-client.slang').

defcall postAuthorizeASPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postAuthorizeASPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postRoutingPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postRoutingPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postAdvertise(?ServerJVM,?ServerPrincipal,?Envs,?DstIP,?Path,?Target,?Src,?Token):-
  {
    postAdvertise($ServerJVM,$ServerPrincipal,$Envs,$DstIP,$Path,$Target,$Src,$Token).
  }.

defcall postAdvertiseSD(?ServerJVM,?ServerPrincipal,?Envs,?FromIP,?DstIP,?Path,?Target,?Token):-
  {
    postAdvertiseSD($ServerJVM,$ServerPrincipal,$Envs,$FromIP,$DstIP,$Path,$Target,$Token).
  }.

defcall postInitRoute(?ServerJVM,?ServerPrincipal,?Envs,?DstIP,?Path,?Target) :- 
  {
    postInitRoute($ServerJVM,$ServerPrincipal,$Envs,$DstIP,$Path,$Target).
  }.

defcall postInitRouteSD(?ServerJVM,?ServerPrincipal,?Envs,?FromIP,?DstIP,?Path,?Target) :- 
  {
    postInitRouteSD($ServerJVM,$ServerPrincipal,$Envs,$FromIP,$DstIP,$Path,$Target).
  }.

defcall postASTagAclEntry(?ServerJVM,?ServerPrincipal,?Envs,?Tag,?Prefix) :- 
  {
    postASTagAclEntry($ServerJVM,$ServerPrincipal,$Envs,$Tag,$Prefix).
  }.

defcall postASTagAclEntrySD(?ServerJVM,?ServerPrincipal,?Envs,?Tag,?SrcPrefix,?DstPrefix) :-
  {
    postASTagAclEntrySD($ServerJVM,$ServerPrincipal,$Envs,$Tag,$SrcPrefix,$DstPrefix).
  }.

defcall postSdPolicySet(?ServerJVM,?ServerPrincipal,?Envs,?Prefix,?PeerPrefix) :- 
  {
    postSdPolicySet($ServerJVM,$ServerPrincipal,$Envs,$Prefix,$PeerPrefix).
  }.

defcall verifyRoute(?ServerJVM,?ServerPrincipal,?Envs,?Owner,?DstIP,?Path,?Token):-
  {
    verifyRoute($ServerJVM,$ServerPrincipal,$Envs,$Owner,$DstIP,$Path,$Token).
  }.

defcall verifyRouteSD(?ServerJVM,?ServerPrincipal,?Envs,?Owner,?FromIP,?DstIP,?Path,?Token):-
  {
    verifyRouteSD($ServerJVM,$ServerPrincipal,$Envs,$Owner, $FromIP,$DstIP,$Path,$Token).
  }.

defcall verifyCompliantPath(?ServerJVM,?ServerPrincipal,?Envs,?Owner,?FromIP,?DstIP,?Path,?Token1,?Token2):-
  {
    verifyCompliantPath($ServerJVM,$ServerPrincipal,$Envs,$Owner,$FromIP,$DstIP,$Path,$Token1,$Token2).
  }.
