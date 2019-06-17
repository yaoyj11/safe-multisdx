import('../stitch-all-client.slang').

defcall postAuthorizeASPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postAuthorizeASPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postRoutingPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postRoutingPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postAdvertise(?ServerJVM,?ServerPrincipal,?Envs,?DstIP,?Path,?Target,?Src,?Len):-
  {
    postAdvertise($ServerJVM,$ServerPrincipal,$Envs,$DstIP,$Path,$Target,$Src,$Len).
  }.

defcall postAdvertiseSD(?ServerJVM,?ServerPrincipal,?Envs,?FromIP,?DstIP,?Path,?Target,?Src,?Len):-
  {
    postAdvertiseSD($ServerJVM,$ServerPrincipal,$Envs,$FromIP,$DstIP,$Path,$Target,$Src,$Len).
  }.

defcall postInitRoute(?ServerJVM,?ServerPrincipal,?Envs,?DstIP,?Path,?Target,?Len) :- 
  {
    postInitRoute($ServerJVM,$ServerPrincipal,$Envs,$DstIP,$Path,$Target,$Len).
  }.

defcall postInitRouteSD(?ServerJVM,?ServerPrincipal,?Envs,?FromIP,?DstIP,?Path,?Target,?Len) :- 
  {
    postInitRouteSD($ServerJVM,$ServerPrincipal,$Envs,$FromIP,$DstIP,$Path,$Target,$Len).
  }.

defcall postASTagAclEntry(?ServerJVM,?ServerPrincipal,?Envs,?Tag,?Prefix) :- 
  {
    postASTagAclEntry($ServerJVM,$ServerPrincipal,$Envs,$Tag,$Prefix).
  }.

defcall postASTagAclEntrySD(?ServerJVM,?ServerPrincipal,?Envs,?Tag,?Prefix,?PeerPrefix) :- 
  {
    postASTagAclEntrySD($ServerJVM,$ServerPrincipal,$Envs,$Tag,$Prefix,$PeerPrefix).
  }.

defcall postSdPolicySet(?ServerJVM,?ServerPrincipal,?Envs,?Prefix,?PeerPrefix) :- 
  {
    postSdPolicySet($ServerJVM,$ServerPrincipal,$Envs,$Prefix,$PeerPrefix).
  }.

defcall postPathToken(?ServerJVM,?ServerPrincipal,?Envs,?Token,?DstIP,?Src,?Len):-
  {
    postPathToken($ServerJVM,$ServerPrincipal,$Envs,$Token,$DstIP,$Src,$Len).
  }.

defcall postPathTokenSD(?ServerJVM,?ServerPrincipal,?Envs,?Token,?FromIP,?DstIP,?Src,?Len):-
  {
    postPathTokenSD($ServerJVM,$ServerPrincipal,$Envs,$Token,$FromIP,$DstIP,$Src,$Len).
  }.

defcall postASTagAclEntrySDSet(?SpeakerJVM,?Speaker,?SpeakerEnvs,?Tag,?Prefix, ?PrefixPeer):-
  {
     postASTagAclEntrySD($SpeakerJVM,$Speaker,$SpeakerEnvs,$Tag,$PrefixPeer, $Prefix).
     postASTagAclEntrySD($SpeakerJVM,$Speaker,$SpeakerEnvs,$Tag,$Prefix,$PrefixPeer).
     postSdPolicySet($SpeakerJVM,$Speaker,$SpeakerEnvs,$Prefix,$PrefixPeer).
  }.

advertisePath(?SpeakerJVM,?Speaker,?TargetJVM,?Target,?AdvertiseEnvs,?UpdateEnvs,?DstIP,?Path,?Src,?Len,?Len1):-
  ?Token := postAdvertise(?SpeakerJVM,?Speaker,?AdvertiseEnvs,?DstIP,?Path,?Target,?Src,?Len),
  postPathToken(?TargetJVM,?Target,?UpdateEnvs,?Token,?DstIP,?Speaker,?Len1).

initPath(?SpeakerJVM,?Speaker,?TargetJVM,?Target,?AdvertiseEnvs,?UpdateEnvs,?DstIP,?Path,?Len,?Len1):-
  ?Token := postInitRoute(?SpeakerJVM,?Speaker,?AdvertiseEnvs,?DstIP,?Path,?Target,?Len),
  postPathToken(?TargetJVM,?Target,?UpdateEnvs,?Token,?DstIP,?Speaker,?Len1).

advertisePathSD(?SpeakerJVM,?Speaker,?TargetJVM,?Target,?AdvertiseEnvs,?UpdateEnvs,?FromIP,?DstIP,?Path,?Src,?Len,?Len1):-
  ?Token := postAdvertiseSD(?SpeakerJVM,?Speaker,?AdvertiseEnvs,?FromIP,?DstIP,?Path,?Target,?Src,?Len),
  postPathTokenSD(?TargetJVM,?Target,?UpdateEnvs,?Token,?FromIP,?DstIP,?Speaker,?Len1).

initPathSD(?SpeakerJVM,?Speaker,?TargetJVM,?Target,?AdvertiseEnvs,?UpdateEnvs,?FromIP,?DstIP,?Path,?Len,?Len1):-
  ?Token := postInitRouteSD(?SpeakerJVM,?Speaker,?AdvertiseEnvs,?FromIP,?DstIP,?Path,?Target,?Len),
  postPathTokenSD(?TargetJVM,?Target,?UpdateEnvs,?Token,?FromIP,?DstIP,?Speaker,?Len1).

defcall verifyRoute(?ServerJVM,?ServerPrincipal,?Envs,?DstIP,?Path,?Src,?Len):-
  {
    verifyRoute($ServerJVM,$ServerPrincipal,$Envs,$DstIP,$Path,$Src,$Len).
  }.

defcall verifyRouteSD(?ServerJVM,?ServerPrincipal,?Envs,?FromIP,?DstIP,?Path,?Src,?Len):-
  {
    verifyRouteSD($ServerJVM,$ServerPrincipal,$Envs,$FromIP,$DstIP,$Path,$Src,$Len).
  }.

defcall verifyCompliantPath(?ServerJVM,?ServerPrincipal,?Envs,?Owner,?FromIP,?DstIP,?AS,?Token1,?Token2):-
  {
    verifyRouteSD($ServerJVM,$ServerPrincipal,$Envs,$Owner,$FromIP,$DstIP,$AS,$Token1,$Token2).
  }.
