import("../sdx-routing.slang").
//route set, AS set

defcon makeGroupSet(?Group) :-
  spec('Construct a set for a group'),
  {
    label("groups/$Group($PolicyVersion)").
  }.

defpost postGroupSet(?Group) :- [makeGroupSet(?Group)].

defcon addTokenToGroupSet(?Token, ?Group) :-
  spec("Add a link to a group's ID set. Invoked after delegation to this group"),
  {
    link($Token).
    label("groups/$Group($Version)").
  }.

defpost updateGroupSet(?Token, ?Group) :- [addTokenToGroupSet(?Token, ?Group)].

defcon addGroupMember(?Group, ?User, ?Delegatable) :-
  spec('Add a user into a group'),
  ?GroupRef := label($Self, "groups/?Group($Version)"),
  {
    groupMember($Group, $User, $Delegatable).
    link($GroupRef).
    label("groupMember/$Group/$User($Version)").     (* this link should be saved in the subject set of ?User *)
  }.

defpost postGroupMember(?Group, ?User, ?Delegatable) :- [addGroupMember(?Group, ?User, ?Delegatable)].

defcon delegateGroup(?Group, ?ToGroup, ?Delegatable) :-
  spec('Delegate administration to another group'), (* Membership is granted if membership of that group is granted *)
  ?GroupRef := label($Self, "groups/?Group($Version)"),
  {
    nestGroup($Group, $ToGroup, $Delegatable).
    link($GroupRef).
    label("delegateGroup/$Group/$ToGroup($Version)").  (* this link should be saved in the ID set of ?ToGroup *)
  }.

defpost postGroupDelegation(?Group, ?ToGroup, ?Delegatable) :- [delegateGroup(?Group, ?ToGroup, ?Delegatable)].


//
// User (group member)
//

defcon delegateGroupMembership(?User, ?Group, ?Delegatable) :-
  spec('Delegate group membership to another user'),
  ?SubjectSetRef := label("subject($Self)($Version)"),
  {
    delegateMembership($User, $Group, $Delegatable).
    link($SubjectSetRef).
    label("membershipDelegation/$Group/$User($Version)").     (* this link should be saved in the subject set of ?User *)
  }.

defpost postMembershipDelegation(?User, ?Group, ?Delegatable) :- [delegateGroupMembership(?User, ?Group, ?Delegatable)].

//
// Guard
//

defcon memberSet() :-
  spec('Local policies on group membership'),
  {
    membership(?Group, ?User) :-
      membership(?Group, ?User, _).
..
   //
   // If the group root has the membership automatically,.
   // update the root's subject set....
   // membership(?Group, ?User, true) :-
   //   ?GRoot := rootPrincipal(?Group),
   //   ?GRoot = ?User.

    membership(?Group, ?User, ?Delegatable) :-
      ?GRoot := rootPrincipal(?Group),.
      ?GRoot: groupMember(?Group, ?User, ?Delegatable).
....
    membership(?Group, ?User, ?Delegatable) :-
      ?Delegator: delegateMembership(?User, ?Group, ?Delegatable),
      membership(?Group, ?Delegator, true).

    membership(?Group, ?User, ?Delegatable) :-
      ?GRoot := rootPrincipal(?Group),
      ?GRoot: nestGroup(?Group, ?ToGroup, true),.
      membership(?ToGroup, ?User, ?Delegatable).

    membership(?Group, ?User, ?Delegatable) :-
      ?GRoot := rootPrincipal(?Group),
      ?GRoot: nestGroup(?Group, ?ToGroup, false),.
      ?ToGroupRoot := rootPrincipal(?ToGroup),
      ?ToGroupRoot: groupMember(?ToGroup, ?User, ?Delegatable).

//
//  These rules are redundant
//
//    nestGroup(?SrcGroup, ?DstGroup) :-
//      ?SrcOwner := rootPrincipal(?SrcGroup), ?SrcOwner: nestGroup(?SrcGroup, ?DstGroup).
//
//    nestGroup(?SrcGroup, ?DstGroup) :-
//      ?SrcOwner := rootPrincipal(?SrcGroup), ?SrcOwner: nestGroup(?SrcGroup, ?MidGroup),
//      nestGroup(?MidGroup, ?DstGroup).
//

    label('standard-membership-policy($PolicyVersion)').
  }.

definit memberSet().

defcon importPolicy() :-
  spec('Local route import policies'),
  {
    //prefix ownership are checked when validating the route
    accept(?Nb, ?Origin, ?Prefix) :-
      importAS(?Nb, ?Origin).

    accept(?Nb, ?Origin, ?Prefix) :-
      importASSet(?Nb, ?ASSet),
      membership(?ASSet, ?Origin).

    accept(?Nb, ?Origin, ?Prefix) :-
      importRS(?Nb, ?RS),
      membership(?RS, ?Prefix).

    accept(?Nb, ?Origin, ?Prefix) :-
      import(?Nb, _).

    accept(?Nb, ?Origin, ?Prefix) :-
      import(?Nb, ?Prefix).

    label('local import policy($PolicyVersion)').
  }.

definit importPolicy().

defcon exportPolicy() :-
  spec('Local route import policies'),
  {
    //prefix ownership are checked when validating the route
    export(?Nb, ?Origin, ?Prefix) :-
      exportAS(?Nb, ?Origin).

    export(?Nb, ?Origin, ?Prefix) :-
      exportASSet(?Nb, ?ASSet),
      membership(?ASSet, ?Origin).

    export(?Nb, ?Origin, ?Prefix) :-
      exportRS(?Nb, ?RS),
      membership(?RS, ?Prefix).

    export(?Nb, ?Origin, ?Prefix) :-
      export(?Nb, _).

    export(?Nb, ?Origin, ?Prefix) :-
      export(?Nb, ?Prefix).

    label('local export policy($PolicyVersion)').
  }.

definit exportPolicy().

defcon importAS(?Nb, ?AS) :-
  spec('post import AS entry'),
  {
    importAS($Nb, $AS).

    label("Import acls($Version)").
  }.

defpost postImportAS(?Nb, ?AS):- [importAS(?Nb, ?AS)].

defcon importASSet(?Nb, ?ASSet) :-
  spec('post import AS set entry'),
  {
    importASSet($Nb, $ASSet).

    label("Import acls($Version)").
  }.

defpost postImportASSet(?Nb, ?ASSet):- [importASSet(?Nb, ?ASSet)].

defcon importRS(?Nb, ?RS) :-
  spec('post import RS entry'),
  {
    importRS($Nb, $RS).

    label("Import acls($Version)").
  }.

defpost postImportRS(?Nb, ?RS):- [importRS(?Nb, ?RS)].

defcon importPrefix(?Nb, ?Prefix) :-
  spec('post import RS entry'),
  {
    importPrefix($Nb, $Prefix).

    label("Import acls($Version)").
  }.

defpost postImportPrefix(?Nb, ?Prefix):- [importPrefix(?Nb, ?Prefix)].

defcon exportAS(?Nb, ?AS) :-
  spec('post export AS entry'),
  {
    exportAS($Nb, $AS).

    label("Export acls($Version)").
  }.

defpost postExportAS(?Nb, ?AS):- [exportAS(?Nb, ?AS)].

defcon exportASSet(?Nb, ?ASSet) :-
  spec('post export AS set entry'),
  {
    exportASSet($Nb, $ASSet).

    label("Export acls($Version)").
  }.

defpost postExportASSet(?Nb, ?ASSet):- [exportASSet(?Nb, ?ASSet)].

defcon exportRS(?Nb, ?RS) :-
  spec('post export RS entry'),
  {
    exportRS($Nb, $RS).

    label("Export acls($Version)").
  }.

defpost postExportRS(?Nb, ?RS):- [exportRS(?Nb, ?RS)].

defcon exportPrefix(?Nb, ?Prefix) :-
  spec('post export RS entry'),
  {
    exportPrefix($Nb, $Prefix).

    label("Export acls($Version)").
  }.

defpost postExportPrefix(?Nb, ?Prefix):- [exportPrefix(?Nb, ?Prefix)].
