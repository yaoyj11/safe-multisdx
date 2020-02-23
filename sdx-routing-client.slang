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

//defcall postPathToken(?ServerJVM,?ServerPrincipal,?Envs,?Token,?DstIP,?Src,?Len):-
//  {
//    postPathToken($ServerJVM,$ServerPrincipal,$Envs,$Token,$DstIP,$Src,$Len).
//  }.
//
//defcall postPathTokenSD(?ServerJVM,?ServerPrincipal,?Envs,?Token,?FromIP,?DstIP,?Src,?Len):-
//  {
//    postPathTokenSD($ServerJVM,$ServerPrincipal,$Envs,$Token,$FromIP,$DstIP,$Src,$Len).
//  }.

defcall postASTagAclEntrySDSet(?SpeakerJVM,?Speaker,?SpeakerEnvs,?Tag,?Prefix,?PrefixPeer):-
  {
//     postASTagAclEntrySD($SpeakerJVM,$Speaker,$SpeakerEnvs,$Tag,$PrefixPeer, $Prefix).
     postASTagAclEntrySD($SpeakerJVM,$Speaker,$SpeakerEnvs,$Tag,$Prefix,$PrefixPeer).
//     postSdPolicySet($SpeakerJVM,$Speaker,$SpeakerEnvs,$Prefix,$PrefixPeer).
  }.

//postASTagAclEntrySDPair(?SpeakerJVM,?Speaker,?TargetJVM,?Target,?SpeakerEnvs,?UpdateEnvs,?Tag,?Prefix,?PeerPrefix):-
//  postASTagAclEntrySDSet(?SpeakerJVM,?Speaker,?SpeakerEnvs,?Tag,?Prefix,?PeerPrefix),
//  postASTagAclEntrySDSet(?TargetJVM,?Target,?UpdateEnvs,?Tag,?PeerPrefix,?Prefix).
//
//advertisePath(?SpeakerJVM,?Speaker,?TargetJVM,?Target,?AdvertiseEnvs,?UpdateEnvs,?DstIP,?Path,?Src,?Len,?Len1):-
//  ?Token := postAdvertise(?SpeakerJVM,?Speaker,?AdvertiseEnvs,?DstIP,?Path,?Target,?Src,?Len),
//  postPathToken(?TargetJVM,?Target,?UpdateEnvs,?Token,?DstIP,?Speaker,?Len1).
//
//initPath(?SpeakerJVM,?Speaker,?TargetJVM,?Target,?AdvertiseEnvs,?UpdateEnvs,?DstIP,?Path,?Len,?Len1):-
//  ?Token := postInitRoute(?SpeakerJVM,?Speaker,?AdvertiseEnvs,?DstIP,?Path,?Target,?Len),
//  postPathToken(?TargetJVM,?Target,?UpdateEnvs,?Token,?DstIP,?Speaker,?Len1).
//
//advertisePathSD(?SpeakerJVM,?Speaker,?TargetJVM,?Target,?AdvertiseEnvs,?UpdateEnvs,?FromIP,?DstIP,?Path,?Src,?Len,?Len1):-
//  ?Token := postAdvertiseSD(?SpeakerJVM,?Speaker,?AdvertiseEnvs,?FromIP,?DstIP,?Path,?Target,?Src,?Len),
//  postPathTokenSD(?TargetJVM,?Target,?UpdateEnvs,?Token,?FromIP,?DstIP,?Speaker,?Len1).
//
//initPathSD(?SpeakerJVM,?Speaker,?TargetJVM,?Target,?AdvertiseEnvs,?UpdateEnvs,?FromIP,?DstIP,?Path,?Len,?Len1):-
//  ?Token := postInitRouteSD(?SpeakerJVM,?Speaker,?AdvertiseEnvs,?FromIP,?DstIP,?Path,?Target,?Len),
//  postPathTokenSD(?TargetJVM,?Target,?UpdateEnvs,?Token,?FromIP,?DstIP,?Speaker,?Len1).

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
