import("../sdx-routing-client.slang").

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


defcall postImportAS(?Nb, ?AS) :-
  {
     postImportAS($Nb, $AS).
  }.

defcall postImportASSet(?Nb, ?ASSet) :-
  {
     postImportASSet($Nb, $ASSet).
  }.

defcall postImportRS(?Nb, ?RS) :-
  {
     postImportRS($Nb, $RS).
  }.

defcall postImportPrefix(?Nb, ?Prefix) :-
  {
     postImportPrefix($Nb, $Prefix).
  }.

defcall postExportAS(?Nb, ?AS) :-
  {
     postExportAS($Nb, $AS).
  }.

defcall postExportASSet(?Nb, ?ASSet) :-
  {
     postExportASSet($Nb, $ASSet).
  }.

defcall postExportRS(?Nb, ?RS) :-
  {
     postExportRS($Nb, $RS).
  }.

defcall postExportPrefix(?Nb, ?Prefix) :-
  {
     postExportPrefix($Nb, $Prefix).
  }.
