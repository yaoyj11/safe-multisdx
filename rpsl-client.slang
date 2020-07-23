import("../sdx-routing-client.slang").

defcall postMatchPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postMatchPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postImportPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postImportPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postExportPolicy(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postExportPolicy($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postMemberSet(?ServerJVM,?ServerPrincipal,?Envs) :-
  {
    postMemberSet($ServerJVM,$ServerPrincipal,$Envs).
  }.

defcall postGroupSet(?ServerJVM, ?ServerPrincipal, ?Envs, ?Group) :-
  {
    postGroupSet($ServerJVM, $ServerPrincipal, $Envs, $Group).
  }.

defcall updateGroupSet(?ServerJVM, ?ServerPrincipal, ?Envs, ?Token, ?Group) :-
  {
    updateGroupSet($ServerJVM, $ServerPrincipal, $Envs, $Token, $Group).
  }.

defcall postGroupMember(?ServerJVM, ?ServerPrincipal, ?Envs, ?GroupId, ?SubjectId, ?Delegatable) :-
  {
    postGroupMember($ServerJVM, $ServerPrincipal, $Envs, $GroupId, $SubjectId, $Delegatable).
  }.

groupMember(?GAJVM, ?GA, ?SubjectJVM, ?SubjectId, ?PostEnvs, ?UpdateEnvs, ?GroupId, ?Delegatable) :-
  ?Token := postGroupMember(?GAJVM, ?GA, ?PostEnvs, ?GroupId, ?SubjectId, ?Delegatable),
  updateSubjectSet(?SubjectJVM, ?SubjectId, ?UpdateEnvs, ?Token).

routeSetMember(?GAJVM, ?GA, ?SubjectJVM, ?SubjectId, ?PostEnvs, ?UpdateEnvs, ?GroupId, ?Prefix, ?Delegatable) :-
  ?Token := postGroupMember(?GAJVM, ?GA, ?PostEnvs, ?GroupId, ?Prefix, ?Delegatable),
  updateSubjectSet(?SubjectJVM, ?SubjectId, ?UpdateEnvs, ?Token).

defcall postImportCapSet(?ServerJVM, ?ServerPrincipal, ?Envs) :-
  {
    postImportCapSet($ServerJVM, $ServerPrincipal, $Envs).
  }.

defcall updateImportCapSet(?ServerJVM, ?ServerPrincipal, ?Envs, ?Token) :-
  {
    updateImportCapSet($ServerJVM, $ServerPrincipal, $Envs, $Token).
  }.

defcall postExportCapSet(?ServerJVM, ?ServerPrincipal, ?Envs) :-
  {
    postExportCapSet($ServerJVM, $ServerPrincipal, $Envs).
  }.

defcall updateExportCapSet(?ServerJVM, ?ServerPrincipal, ?Envs, ?Token) :-
  {
    updateExportCapSet($ServerJVM, $ServerPrincipal, $Envs, $Token).
  }.


defcall postGroupDelegation(?ServerJVM, ?ServerPrincipal, ?Envs, ?GroupId, ?ToGroupId, ?Delegatable) :-
  {
    postGroupDelegation($ServerJVM, $ServerPrincipal, $Envs, $GroupId, $ToGroupId, $Delegatable).
  }.

// ?GA := rootPrincipal(?GroupId)
// ?SubjectId := rootPrincipal(?ToGroupId)
nestGroup(?GAJVM, ?GA, ?SubjectJVM, ?SubjectId, ?PostEnvs, ?UpdateEnvs, ?GroupId, ?ToGroupId, ?Delegatable) :- 
  ?Token := postGroupDelegation(?GAJVM, ?GA, ?PostEnvs, ?GroupId, ?ToGroupId, ?Delegatable),
  updateGroupSet(?SubjectJVM, ?SubjectId, ?UpdateEnvs, ?Token, ?ToGroupId).
  
defcall postMembershipDelegation(?ServerJVM, ?ServerPrincipal, ?Envs, ?SubjectId, ?GroupId, ?Delegatable) :-
  {
    postMembershipDelegation($ServerJVM, $ServerPrincipal, $Envs, $SubjectId, $GroupId, $Delegatable).
  }.

delegateMembership(?ServerJVM, ?ServerPrincipal, ?SubjectJVM, ?SubjectId, ?PostEnvs, ?UpdateEnvs, ?GroupId, ?Delegatable) :- 
  ?Token := postMembershipDelegation(?ServerJVM, ?ServerPrincipal, ?PostEnvs, ?SubjectId, ?GroupId, ?Delegatable),
  updateSubjectSet(?SubjectJVM, ?SubjectId, ?UpdateEnvs, ?Token).


defcall postImportAclOther(?ServerJVM, ?ServerPrincipal, ?Envs, ?AsSet, ?RouteSet) :-
  {
     postImportAclOther($ServerJVM, $ServerPrincipal, $Envs, $AsSet, $RouteSet).
  }.

defcall postImportAcl(?ServerJVM, ?ServerPrincipal, ?Envs, ?AsSet, ?RouteSet) :-
  {
     postImportAcl($ServerJVM, $ServerPrincipal, $Envs, $AsSet, $RouteSet).
  }.

groupImportAcl(?ServerJVM, ?SA, ?SubjectJVM, ?SubjectId, ?PostEnvs, ?UpdateEnvs, ?ToGroupId, ?RouteSet) :-
  ?Token := postImportAcl(?ServerJVM, ?SA, ?PostEnvs, ?ToGroupId, ?RouteSet),
  updateGroupSet(?SubjectJVM, ?SubjectId, ?UpdateEnvs, ?Token, ?ToGroupId).

asImportAcl(?ServerJVM, ?SA, ?SubjectJVM, ?SubjectId, ?PostEnvs, ?UpdateEnvs, ?RouteSet) :-
  ?Token := postImportAcl(?ServerJVM, ?SA, ?PostEnvs, ?SubjectId, ?RouteSet),
  updateImportCapSet(?SubjectJVM, ?SubjectId, ?UpdateEnvs, ?Token).


defcall postExportAclOther(?ServerJVM, ?ServerPrincipal, ?Envs, ?AsSet, ?RouteSet) :-
  {
     postExportAclOther($ServerJVM, $ServerPrincipal, $Envs, $AsSet, $RouteSet).
  }.

defcall postExportAcl(?ServerJVM, ?ServerPrincipal, ?Envs, ?AsSet, ?RouteSet) :-
  {
     postExportAcl($ServerJVM, $ServerPrincipal, $Envs, $AsSet, $RouteSet).
  }.

groupExportAcl(?ServerJVM, ?SA, ?SubjectJVM, ?SubjectId, ?PostEnvs, ?UpdateEnvs, ?ToGroupId, ?RouteSet) :-
  ?Token := postExportAcl(?ServerJVM, ?SA, ?PostEnvs, ?ToGroupId, ?RouteSet),
  updateGroupSet(?SubjectJVM, ?SubjectId, ?UpdateEnvs, ?Token, ?ToGroupId).

asExportAcl(?ServerJVM, ?SA, ?SubjectJVM, ?SubjectId, ?PostEnvs, ?UpdateEnvs, ?RouteSet) :-
  ?Token := postExportAcl(?ServerJVM, ?SA, ?PostEnvs, ?SubjectId, ?RouteSet),
  updateExportCapSet(?SubjectJVM, ?SubjectId, ?UpdateEnvs, ?Token).


defcall importRoute(?ServerJVM, ?ServerPrincipal, ?Envs, ?Nb, ?Origin, ?Prefix) :-
  {
    importRoute($ServerJVM, $ServerPrincipal, $Envs, $Nb, $Origin, $Prefix).
  }.

defcall exportRoute(?ServerJVM, ?ServerPrincipal, ?Envs, ?Nb, ?Origin, ?Prefix) :-
  {
    exportRoute($ServerJVM, $ServerPrincipal, $Envs, $Nb, $Origin, $Prefix).
  }.
