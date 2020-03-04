import('../base-client.slang').
//Used defcall
//postIdSet
//postSubjectSet
//updateSubjectSet
//postProjectSet
//postStandarSliceControlSet
//postSliceSet


defcall postTagSet(?ServerJVM,?ServerPrincipal,?Envs,?Tag):-
  {
    postTagSet($ServerJVM,$ServerPrincipal,$Envs,$Tag).
  }.

defcall postMakeTagSubjectSet(?ServerJVM,?ServerPrincipal,?Envs):-
  {
    postMakeTagSubjectSet($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall updateTagSet(?ServerJVM,?ServerPrincipal,?Envs,?Token,?Tag):-
  {
    updateTagSet($ServerJVM,$ServerPrincipal,$Envs,$Token,$Tag).
  }.

defcall postGrantTagPriv(?ServerJVM,?ServerPrincipal,?Envs,?User,?Tag, ?Delegatable):-
  {
    postGrantTagPriv($ServerJVM,$ServerPrincipal,$Envs,$User,$Tag, $Delegatable).
  }.

defcall postAclEntrySet(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postAclEntrySet($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postUserAclEntry(?ServerJVM,?ServerPrincipal,?Envs,?User) :-
  {
    postUserAclEntry($ServerJVM,$ServerPrincipal,$Envs,$User).
  }.

defcall postUserTagAclEntry(?ServerJVM,?ServerPrincipal,?Envs,?Tag) :-
  {
    postUserTagAclEntry($ServerJVM,$ServerPrincipal,$Envs,$Tag).
  }.

defcall postTagPrivilegePolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postTagPrivilegePolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postOwnPrefixPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postOwnPrefixPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

tagPrivDelegation(?FromJVM,?FromPrincipal,?ToJVM,?ToPrincipal,?GrantEnvs,?UpdateEnvs,?Tag,?Delegatable):-
  ?Token := postGrantTagPriv(?FromJVM,?FromPrincipal,?GrantEnvs,?ToPrincipal,?Tag,?Delegatable),
  updateTagSet(?ToJVM,?ToPrincipal,?UpdateEnvs,?Token,?Tag).

//
//Customer
//

defcall postIPAllocate(?ServerJVM,?ServerPrincipal,?Envs,?Prcpl,?Prefix, ?DlgPrefix):-
  {
    postIPAllocate($ServerJVM,$ServerPrincipal,$Envs,$Prcpl,$Prefix,$DlgPrefix).
  }.

defcall postDlgToken(?ServerJVM,?ServerPrincipal,?Envs,?Token, ?Prefix):-
  {
    postDlgToken($ServerJVM,$ServerPrincipal,$Envs,$Token, $Prefix).
  }.

allocatePrefix(?RpkiRootJVM,?RpkiRoot,?IRJVM,?IR,?AllocateEnvs,?UpdateEnvs,?Prefix,?DlgPrefix):-
  ?Token := postIPAllocate(?RpkiRootJVM,?RpkiRoot,?AllocateEnvs,?IR,?Prefix,?DlgPrefix),
  postDlgToken(?IRJVM,?IR,?UpdateEnvs,?Token, ?Prefix).

defcall postMakeIPTokenSet(?ServerJVM,?ServerPrincipal,?Envs, ?Prefix):-
  {
    postMakeIPTokenSet($ServerJVM,$ServerPrincipal,$Envs, $Prefix).
  }.

