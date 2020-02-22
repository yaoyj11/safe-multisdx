import('../mp_geni_fine.slang').
//Used defcall
//postIdSet
//postSubjectSet
//updateSubjectSet
//postProjectSet
//postStandarSliceControlSet
//postSliceSet

//begin of mp_geni

//end of mp_geni

//defpost policies
defcall postTrustStructure(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postTrustStructure($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postRegisteredUserPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postRegisteredUserPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.
defcall postProjectPolicySet(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postProjectPolicySet($ServerJVM,$ServerPrincipal,$Envs).
  }.
defcall postSlicePolicySet(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postSlicePolicySet($ServerJVM,$ServerPrincipal,$Envs).
  }.
defcall postAggregatePolicySet(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postAggregatePolicySet($ServerJVM,$ServerPrincipal,$Envs).
  }.
////

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

defcall postLinkTagSetToProject(?ServerJVM,?ServerPrincipal,?Envs, ?ProjectId,?TagSetRef):-
  {
    postLinkTagSetToProject($ServerJVM,$ServerPrincipal,$Envs,$ProjectId,$TagSetRef).
  }.

defcall postLinkTagSetToSlice(?ServerJVM,?ServerPrincipal,?Envs, ?SliceId,?TagSetRef):-
  {
    postLinkTagSetToSlice($ServerJVM,$ServerPrincipal,$Envs,$SliceId,$TagSetRef).
  }.

defcall postObjectTagSet(?ServerJVM,?ServerPrincipal,?Envs, ?ObjectId,?Tag):-
  {
    postObjectTagSet($ServerJVM,$ServerPrincipal,$Envs,$ObjectId,$Tag).
  }.

defcall postUpdateObjectTagSet(?ServerJVM,?ServerPrincipal,?Envs, ?ObjectId,?Tag,?Token):-
  {
    postUpdateObjectTagSet($ServerJVM,$ServerPrincipal,$Envs,$ObjectId,$Tag,$Token).
  }.

defcall postGrantTagPriv(?ServerJVM,?ServerPrincipal,?Envs,?User,?Tag, ?Delegatable):-
  {
    postGrantTagPriv($ServerJVM,$ServerPrincipal,$Envs,$User,$Tag, $Delegatable).
  }.

defcall postAssignTag(?ServerJVM,?ServerPrincipal,?Envs,?Slice, ?Tag) :-
  {
    postAssignTag($ServerJVM,$ServerPrincipal,$Envs,$Slice,$Tag).
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

defcall postSliceTagAclEntry(?ServerJVM,?ServerPrincipal,?Envs,?Tag) :-
  {
    postSliceTagAclEntry($ServerJVM,$ServerPrincipal,$Envs,$Tag).
  }.

defcall postProjectTagAclEntry(?ServerJVM,?ServerPrincipal,?Envs,?Tag) :-
  {
    postTagAclEntry($ServerJVM,$ServerPrincipal,$Envs,$Tag).
  }.


defcall postProjectIDAcl(?ServerJVM,?ServerPrincipal,?Envs,?PID) :-
  {
    postProjectIDAcl($ServerJVM,$ServerPrincipal,$Envs,$PID).
  }.

defcall postStitchPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postStitchPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postTagPrivilegePolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postTagPrivilegePolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.


controlPrivilegeDelegation(?FromJVM,?FromPrincipal,?ToJVM,?ToPrincipal,?GrantEnvs,?UpdateEnvs,?Slice,?Priv,?Delegatable):-
  ?Token := postTagDelegation(?FromJVM,?FromPrincipal,?GrantEnvs,?Slice,?Priv,?Delegatable),
  updateSubjectSet(?ToJVM,?ToPrincipal,?UpdateEnvs,?Token).

tagPrivDelegation(?FromJVM,?FromPrincipal,?ToJVM,?ToPrincipal,?GrantEnvs,?UpdateEnvs,?Tag,?Delegatable):-
  ?Token := postGrantTagPriv(?FromJVM,?FromPrincipal,?GrantEnvs,?ToPrincipal,?Tag,?Delegatable),
  updateTagSet(?ToJVM,?ToPrincipal,?UpdateEnvs,?Token,?Tag).

assignTagToObject(?FromJVM,?FromPrincipal,?ToJVM,?ToPrincipal,?GrantEnvs,?UpdateEnvs,?ObjectId,?Tag):-
  ?Token := postAssignTag(?FromJVM,?FromPrincipal,?GrantEnvs,?ObjectId,?Tag),
  postUpdateObjectTagSet(?ToJVM,?ToPrincipal,?UpdateEnvs,?ObjectId,?Tag,?Token).

assignTagToSlice(?FromJVM,?FromPrincipal,?ToJVM,?ToPrincipal,?GrantEnvs,?UpdateEnvs,?SliceId,?Tag):-
  ?Token := postAssignTag(?FromJVM,?FromPrincipal,?GrantEnvs,?SliceId,?Tag),
  postLinkTagSetToSlice(?ToJVM,?ToPrincipal,?UpdateEnvs,?SliceId,?Token).

assignTagToProject(?FromJVM,?FromPrincipal,?ToJVM,?ToPrincipal,?GrantEnvs,?UpdateEnvs,?ProjectId,?Tag):-
  ?Token := postAssignTag(?FromJVM,?FromPrincipal,?GrantEnvs,?ProjectId,?Tag),
  postLinkTagSetToProject(?ToJVM,?ToPrincipal,?UpdateEnvs,?ProjectId,?Token).

defcall authorizeStitchByUID(?ServerJVM, ?ServerPrincipal, ?Envs, ?User, ?Slice, ?Token1, ?Token2) :-
  {
    authorizeStitchByUID($ServerJVM,$ServerPrincipal,$Envs,$User,$Slice, $Token1, $Token2).
  }.

defcall authorizeStitchByUserAttr(?ServerJVM, ?ServerPrincipal, ?Envs, ?User, ?Slice, ?Tag, ?Token1, ?Token2, ?Token3) :-
  {
    authorizeStitchByUserAttr($ServerJVM,$ServerPrincipal,$Envs,$User,$Slice, $Tag, $Token1, $Token2, $Token3).
  }.

defcall authorizeStitchBySliceAttr(?ServerJVM, ?ServerPrincipal, ?Envs, ?User, ?Slice, ?Tag, ?Token1, ?Token2, ?Token3) :-
  {
    authorizeStitchBySliceAttr($ServerJVM,$ServerPrincipal,$Envs,$User,$Slice, $Tag, $Token1, $Token2, $Token3).
  }.

defcall authorizeStitchByPID(?ServerJVM, ?ServerPrincipal, ?Envs, ?User, ?Slice, ?Token1, ?Token2, ?Token3) :-
  {
    authorizeStitchByPID($ServerJVM,$ServerPrincipal,$Envs,$User,$Slice, $Token1, $Token2, $Token3).
  }.

defcall authorizeStitchByProjectAttr(?ServerJVM, ?ServerPrincipal, ?Envs, ?User, ?Slice, ?Tag, ?Token1, ?Token2, ?Token3) :-
  {
    authorizeStitchByProjectAttr($ServerJVM,$ServerPrincipal,$Envs,$User,$Slice, $Tag, $Token1, $Token2, $Token3).
  }.

defcall authorizeConnect(?ServerJVM, ?ServerPrincipal, ?Envs, ?Alice, ?IPa, ?Bob, ?IPb) :-
  {
    authorizeConnect($ServerJVM,$ServerPrincipal,$Envs,$Alice, $IPa, $Bob, $IPb).
  }.

defcall authZByPID(?ServerJVM, ?ServerPrincipal, ?Envs, ?Alice, ?IPa, ?Bob, ?IPb, ?Token1, ?Token2, ?Token3, ?Token4, ?Token5, ?Token6, ?Token7) :-
  {
    authZByPID($ServerJVM,$ServerPrincipal,$Envs,$Alice, $IPa, $Bob, $IPb, $Token1, $Token2, $Token3, $Token4, $Token5,$Token6, $Token7).
  }.

defcall authZByProjectAttr(?ServerJVM, ?ServerPrincipal, ?Envs, ?Alice, ?IPa, ?Bob, ?IPb, ?Token1, ?Token2, ?Token3, ?Token4, ?Token5,?Token6, ?Token7) :-
  {
    authZByProjectAttr($ServerJVM,$ServerPrincipal,$Envs,$Alice, $IPa, $Bob, $IPb, $Token1, $Token2, $Token3, $Token4, $Token5,$Token6, $Token7).
  }.

defcall authZByUserAttr(?ServerJVM, ?ServerPrincipal, ?Envs, ?Alice, ?IPa, ?Bob, ?IPb, ?Token1, ?Token2, ?Token3, ?Token4, ?Token5,?Token6,?Token7,?Token8,?Token9) :-
  {
    authZByUserAttr($ServerJVM,$ServerPrincipal,$Envs,$Alice, $IPa, $Bob, $IPb, $Token1, $Token2, $Token3, $Token4, $Token5,$Token6,$Token7,$Token8,$Token9).
  }.

//
//Customer
//
defcall postLinkPolicySet(?ServerJVM,?ServerPrincipal,?Envs,?PolicySet) :-
  {
    postLinkPolicySet($ServerJVM,$ServerPrincipal,$Envs,$PolicySet).
  }.

defcall postCustomerConnectionPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postCustomerConnectionPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postCustomerPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postCustomerPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

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

