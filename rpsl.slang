import("../sdx-routing.slang").
import("../base.slang").
//route set, AS set

defcon makeGroupSet(?Group) :-
  spec('Construct a set for a group'),
  {
    label("groups/$Group($Version)").
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

    membership(?Group, ?User, ?Delegatable) :-
      ?GRoot := rootPrincipal(?Group),
      ?GRoot: groupMember(?Group, ?User, ?Delegatable).

    membership(?Group, ?User, ?Delegatable) :-
      ?Delegator: delegateMembership(?User, ?Group, ?Delegatable),
      membership(?Group, ?Delegator, true).

    membership(?Group, ?User, ?Delegatable) :-
      ?GRoot := rootPrincipal(?Group),
      ?GRoot: nestGroup(?Group, ?ToGroup, true),
      membership(?ToGroup, ?User, ?Delegatable).

    membership(?Group, ?User, ?Delegatable) :-
      ?GRoot := rootPrincipal(?Group),
      ?GRoot: nestGroup(?Group, ?ToGroup, false),
      ?ToGroupRoot := rootPrincipal(?ToGroup),
      ?ToGroupRoot: groupMember(?ToGroup, ?User, ?Delegatable).

    label("standard-membership-policy($PolicyVersion)").
  }.

definit memberSet().

defpost postMemberSet() :- [memberSet()].

defcon matchPolicy() :-
  spec('Local policy for matching route and policy'),
  {

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      eq(?Nb, ?AsSet),
      eq(?RouteSet, "any").

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      membership(?AsSet, ?Nb),
      eq(?RouteSet, "any").

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      eq(?RouteSet, "peeras"),
      eq(?Nb, ?Origin),
      membership(?AsSet, ?Nb).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      matchA(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      matchB(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      matchC(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      matchD(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      matchE(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      matchF(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      matchG(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      matchH(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).


    matchA(?A, ?B, ?C, ?D, ?E):-
      eq(?A, ?D),
      eq(?B, ?E).

    matchB(?A, ?B, ?C, ?D, ?E):-
      eq(?A, ?D),
      eq(?C, ?E).

    matchC(?A, ?B, ?C, ?D, ?E):-
      eq(?A, ?D),
      membership(?E, ?B).

    matchD(?A, ?B, ?C, ?D, ?E):-
      eq(?A, ?D),
      membership(?E, ?C).

    matchE(?A, ?B, ?C, ?D, ?E):-
      eq(?E, ?B),
      membership(?D, ?A).

    matchF(?A, ?B, ?C, ?D, ?E):-
      eq(?E, ?C),
      membership(?D, ?A).

    matchG(?A, ?B, ?C, ?D, ?E):-
      membership(?D, ?A),
      membership(?E, ?C).

    matchH(?A, ?B, ?C, ?D, ?E):-
      membership(?D, ?A),
      membership(?E, ?B).


    label("match policy($PolicyVersion)").
  }.

definit matchPolicy().

defpost postMatchPolicy() :- [matchPolicy()].

defcon importPolicy() :-
  spec('Local route import policies'),
  {
    //prefix ownership are checked when validating the route
    import(?Nb, ?Origin, ?Prefix) :-
      import(?AsSet, ?RouteSet),
      match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    label("import policy($PolicyVersion)").
  }.

definit importPolicy().

defpost postImportPolicy() :- [importPolicy()].

defcon exportPolicy() :-
  spec('Local route import policies'),
  {
    //prefix ownership are checked when validating the route
    export(?Nb, ?Origin, ?Prefix) :-
      export(?AsSet, ?RouteSet),
      match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet).

    label("export policy($PolicyVersion)").
  }.

definit exportPolicy().

defpost postExportPolicy() :- [exportPolicy()].


defcon importAcl(?AsSet, ?RouteSet) :-
  spec('post import AS entry'),
  {
    import($AsSet, $RouteSet).

    label("import acls($Version)").
  }.

defpost postImportAcl(?AsSet, ?RouteSet):- [importAcl(?AsSet, ?RouteSet)].

defcon exportAcl(?AsSet, ?RouteSet) :-
  spec('post import AS entry'),
  {
    export($AsSet, $RouteSet).

    label("export acls($Version)").
  }.

defpost postExportAcl(?AsSet, ?RouteSet):- [exportAcl(?AsSet, ?RouteSet)].

defguard importRoute(?Nb, ?Origin, ?Prefix) :-
  ?NbSubjectSet := label(?Nb, "subject(?Nb)($Version)"),
  ?OriginSubjectSet := label(?Origin, "subject(?Origin)($Version)"),
  ?ImportAclSet := label("import acls($Version)"),
  ?ImportPolicySet := label("import policy($PolicyVersion)"),
  ?MatchPolicy := label("match policy($PolicyVersion)"),
  ?MemberSet := label("standard-membership-policy($PolicyVersion)"),
  {
    link($NbSubjectSet).
    link($OriginSubjectSet).
    link($MatchPolicy).
    link($ImportAclSet).
    link($MemberSet).
    link($ImportPolicySet).

    import($Nb, $Origin, $Prefix)?
  }.

defguard exportRoute(?Nb, ?Origin, ?Prefix) :-
  ?NbSubjectSet := label(?Nb, "subject(?Nb)($Version)"),
  ?OriginSubjectSet := label(?Origin, "subject(?Origin)($Version)"),
  ?ExportAclSet := label("export acls($Version)"),
  ?ExportPolicySet := label("export policy($PolicyVersion)"),
  ?MatchPolicy := label("match policy($PolicyVersion)"),
  ?MemberSet := label("standard-membership-policy($PolicyVersion)"),
  {
    link($NbSubjectSet).
    link($OriginSubjectSet).
    link($MatchPolicy).
    link($MemberSet).
    link($ExportAclSet).
    link($ExportPolicySet).

    export($Nb, $Origin, $Prefix)?
  }.
