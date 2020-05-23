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

defcon matchPolicy():-
  spec('Local policy for matching route and policy'),
  {
    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      eq(?Nb, ?AsSet),
      eq(?Origin, ?RouteSet).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      eq(?Nb, ?AsSet),
      eq(?Prefix, ?RouteSet).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      eq(?Nb, ?AsSet),
      membership(?RouteSet, ?Origin).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      eq(?Nb, ?AsSet),
      membership(?RouteSet, ?Prefix).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      eq(?RouteSet, ?Origin),
      membership(?AsSet, ?Nb).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      eq(?RouteSet, ?Prefix),
      membership(?AsSet, ?Nb).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      membership(?AsSet, ?Nb),
      membership(?RouteSet, ?Origin).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      membership(?AsSet, ?Nb),
      membership(?RouteSet, ?Prefix).

    label('macth policy($PolicyVersion)').

  }.

defcon importPolicy() :-
  spec('Local route import policies'),
  {
    //prefix ownership are checked when validating the route
    accept(?Nb, ?Origin, ?Prefix) :-
      import(?AsSet, ?RouteSet),
      match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    label('import policy($PolicyVersion)').
  }.

definit importPolicy().

defcon exportPolicy() :-
  spec('Local route import policies'),
  {
    //prefix ownership are checked when validating the route
    export(?Nb, ?Origin, ?Prefix) :-
      export(?AsSet, ?RouteSet),
      match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    label('export policy($PolicyVersion)').
  }.

definit exportPolicy().


defcon importAcl(?AsSet, ?RouteSet) :-
  spec('post import AS entry'),
  {
    import($AsSet, $RouteSet).

    label("Import acls($Version)").
  }.

defpost postImport(?AsSet, ?RouteSet):- [importAcl(?AsSet, ?RouteSet)].

defcon exportAcl(?AsSet, ?RouteSet) :-
  spec('post import AS entry'),
  {
    export($AsSet, $RouteSet).

    label("Import acls($Version)").
  }.

defpost postExport(?AsSet, ?RouteSet):- [exportAcl(?AsSet, ?RouteSet)].
