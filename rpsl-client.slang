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


defcall postImportAcl(?ServerJVM, ?ServerPrincipal, ?Envs, ?AsSet, ?RouteSet) :-
  {
     postImportAcl($ServerJVM, $ServerPrincipal, $Envs, $AsSet, $RouteSet).
  }.

defcall postExportAcl(?ServerJVM, ?ServerPrincipal, ?Envs, ?AsSet, ?RouteSet) :-
  {
     postExportAcl($ServerJVM, $ServerPrincipal, $Envs, $AsSet, $RouteSet).
  }.


defcall importRoute(?ServerJVM, ?ServerPrincipal, ?Envs, ?Nb, ?Origin, ?Prefix) :-
  {
    importRoute($ServerJVM, $ServerPrincipal, $Envs, $Nb, $Origin, $Prefix).
  }.

defcall exportRoute(?ServerJVM, ?ServerPrincipal, ?Envs, ?Nb, ?Origin, ?Prefix) :-
  {
    exportRoute($ServerJVM, $ServerPrincipal, $Envs, $Nb, $Origin, $Prefix).
  }.
