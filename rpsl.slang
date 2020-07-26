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

//defcon makeImportCapSet() :-
//  spec('Construct a set for neighbor statements accepting routes'),
//  {
//    label("importcapset($Version)").
//  }.
//
//defpost postImportCapSet() :- [makeImportCapSet()].
//
//defcon addTokenToImportCapSet(?Token) :-
//  spec("Add a link to import cap set, invoked after deletation to this nsp"),
//  {
//    link($Token).
//    label("importcapset($Version)").
//  }.
//
//defpost updateImportCapSet(?Token) :- [addTokenToImportCapSet(?Token)].
//
//defcon makeExportCapSet() :-
//  spec('Construct a set for neighbor statements exporting routes'),
//  {
//    label("exportcapset($Version)").
//  }.
//
//defpost postExportCapSet() :- [makeExportCapSet()].

defcon makeImportAclSet(?AS) :-
  spec('make import acl set'),
  {
    label("import acls/$AS($Version)").
  }.

defpost postImportAclSet(?AS):- [makeImportAclSet(?AS)].

defcon makeExportAclSet(?AS) :-
  spec('make export acl set'),
  {
    label("export acls/$AS($Version)").
  }.

defpost postExportAclSet(?AS):- [makeExportAclSet(?AS)].

defcon addTokenToExportCapSet(?Token) :-
  spec("Add a link to export cap set, invoked after deletation to this nsp"),
  {
    link($Token).
    label("exportcapset($Version)").
  }.

defpost updateExportCapSet(?Token) :- [addTokenToExportCapSet(?Token)].

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
      nbMatch(?Nb, ?AsSet),
      routeMatch(?Origin, ?Prefix, ?RouteSet).

    match(?Nb, ?Origin, ?Prefix, ?AsSet, ?RouteSet) :-
      nbMatch(?Nb, ?AsSet),
      eq(?RouteSet, "peeras"),
      eq(?Nb, ?Origin).

    nbMatch(?Nb, ?AsSet) :-
      eq(?AsSet, "any").

    nbMatch(?Nb, ?AsSet) :-
      eq(?Nb, ?AsSet).

    nbMatch(?Nb, ?AsSet) :-
      membership(?AsSet, ?Nb).

    routeMatch(?Origin, ?Prefix, ?RouteSet) :-
      eq(?RouteSet, "any").

    routeMatch(?Origin, ?Prefix, ?RouteSet) :-
      originMatch(?RouteSet, ?Origin).

    routeMatch(?Origin, ?Prefix, ?RouteSet) :-
      prefixMatch(?RouteSet, ?Prefix).

    originMatch(?RouteSet, ?Origin) :-
      eq(?RouteSet, ?Origin).

    originMatch(?RouteSet, ?Origin) :-
      membership(?RouteSet, ?Origin).

    prefixMatch(?RouteSet, ?Prefix) :-
      eq(?RouteSet, ?Prefix).

    prefixMatch(?RouteSet, ?Prefix) :-
      membership(?RouteSet, ?Prefix).

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


defcon importAclOther(?AsSet, ?RouteSet) :-
  spec('post import AS entry'),
  {
    import($AsSet, $RouteSet).

    label("import acls($Version)").
  }.

defpost postImportAclOther(?AsSet, ?RouteSet):- [importAclOther(?AsSet, ?RouteSet)].

defcon importAcl(?AsSet, ?RouteSet) :-
  spec('post import AS entry'),
  {
    import($AsSet, $RouteSet).

    label("import acls/$AsSet($Version)").
  }.

defpost postImportAcl(?AsSet, ?RouteSet):- [importAcl(?AsSet, ?RouteSet)].

defcon exportAcl(?AsSet, ?RouteSet) :-
  spec('post import AS entry'),
  {
    export($AsSet, $RouteSet).

    label("export acls/$AsSet($Version)").
  }.

defpost postExportAcl(?AsSet, ?RouteSet):- [exportAcl(?AsSet, ?RouteSet)].

defcon exportAclOther(?AsSet, ?RouteSet) :-
  spec('post import AS entry'),
  {
    export($AsSet, $RouteSet).

    label("export acls($Version)").
  }.

defpost postExportAclOther(?AsSet, ?RouteSet):- [exportAclOther(?AsSet, ?RouteSet)].

defguard importRoute(?Nb, ?Origin, ?Prefix) :-
  ?NbSubjectSet := label(?Nb, "subject(?Nb)($Version)"),
  ?OriginSubjectSet := label(?Origin, "subject(?Origin)($Version)"),
  ?ImportAclSet := label("import acls($Version)"),
  ?NbImportCapSet := label("import acls/?Nb($Version)"),
  ?ImportPolicySet := label("import policy($PolicyVersion)"),
  ?MatchPolicy := label("match policy($PolicyVersion)"),
  ?MemberSet := label("standard-membership-policy($PolicyVersion)"),
  {
    link($NbSubjectSet).
    link($OriginSubjectSet).
    link($MatchPolicy).
    link($ImportAclSet).
    link($NbImportCapSet).
    link($MemberSet).
    link($ImportPolicySet).

    import($Nb, $Origin, $Prefix)?
  }.

defguard exportRoute(?Nb, ?Origin, ?Prefix) :-
  ?NbSubjectSet := label(?Nb, "subject(?Nb)($Version)"),
  ?OriginSubjectSet := label(?Origin, "subject(?Origin)($Version)"),
  ?ExportAclSet := label("export acls($Version)"),
  ?NbExportCapSet := label("export acls/?Nb($Version)"),
  ?ExportPolicySet := label("export policy($PolicyVersion)"),
  ?MatchPolicy := label("match policy($PolicyVersion)"),
  ?MemberSet := label("standard-membership-policy($PolicyVersion)"),
  {
    link($NbSubjectSet).
    link($OriginSubjectSet).
    link($MatchPolicy).
    link($MemberSet).
    link($ExportAclSet).
    link($NbExportCapSet).
    link($ExportPolicySet).

    export($Nb, $Origin, $Prefix)?
  }.
