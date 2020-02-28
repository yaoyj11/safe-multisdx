import("../base.slang").

//
//Users
//We may just link the tag set in user" subject set
//
defenv RpkiRoot() :- "FcHzu-wG1BEHYBljyKf-4l9H3mFqsD2IOObzrhq2KcE".

defcon makeTagSet(?Tag) :-
  spec("Construct the identity set for a tag"),
  {
    label("tags/$Tag($Version)").
  }.

defpost postTagSet(?Tag) :- [makeTagSet(?Tag)].

defcon makeTagSubjectSet() :-
  spec("Construct the identity set for a all tags"),
  {
    label("tags($Version)").
  }.

defpost postMakeTagSubjectSet() :- [makeTagSubjectSet()].

defcon addTokenToTagSet(?Token, ?Tag) :-
  spec("Add a link to a tag's ID set. Invoked after delegation to this tag"),
  {
    link($Token).
    label("tags/$Tag($Version)").
  }.

defcon addTokenToTagSubjectSet(?Token) :-
  spec("Add a link to a tag's ID set. Invoked after delegation to this tag"),
  {
    link($Token).
    label("tags($Version)").
  }.

defpost updateTagSet(?Token, ?Tag) :- [addTokenToTagSet(?Token, ?Tag), addTokenToTagSubjectSet(?Token), addTokenToSubjectSet(?Token)].


//
// Tag Authority 

defcon grantTagPriv(?User, ?Tag, ?Delegatable) :-
  spec("Delegate access for a tag to a user"),
  ?TagRef := label("tags/?Tag($Version)"),
  {
    grantTagPriv($Tag, $User, $Delegatable).
    link($TagRef).
    label("grantTagPriv/$Tag/$User($Version)").
    (* this link should be saved in the subject set of ?User *)
  }.

defpost postGrantTagPriv(?User, ?Tag, ?Delegatable) :- [grantTagPriv(?User, ?Tag, ?Delegatable)].

//The object could be a slice or a project
defcon grantTag(?Object, ?Tag) :-
  ?TagRef := label("tags/?Tag($Version)"),
  {
    assignTag($Object, $Tag).
    link($TagRef).
    label("grantTag/$Object($Version)").
  }.

defpost postAssignTag(?Object, ?Tag) :- [grantTag(?Object, ?Tag)].

//
//SDX
//

defcon aclEntrySet() :-
  {
     label("aclEntry($Version)").
  }.

defpost postAclEntrySet() :- [aclEntrySet()].

defcon userAclEntry(?User) :-
  spec("SDX user access control list"),
  {
    userAclEntry($User).
    label("userAclEntry($Version)").
  }.

defpost postUserAclEntry(?User):- [userAclEntry(?User)].

defcon userTagAclEntry(?Tag) :-
  spec("SDX user access control list"),
  {
    userTagAclEntry($Tag).
    label("userTagAclEntry($Version)").
  }.

defpost postUserTagAclEntry(?Tag) :- [userTagAclEntry(?Tag)].


defcon ownPrefixPolicy():-
  {
    ownPrefix(?Prcpl,?Prefix):-
      $RpkiRoot: allocate(?Prcpl,?Prefix).

    ownPrefix(?Prcpl,?Prefix):-
      ?UpStream: allocate(?Prcpl,?Prefix),
      ownPrefix(?UpStream,?PrefixSet),
      ?Prefix <: ?PrefixSet.
    label("own prefix policy($PolicyVersion)").
  }.

definit ownPrefixPolicy().

defpost postOwnPrefixPolicy() :- [ownPrefixPolicy()].

defcon ipAllocate(?Prcpl,?Prefix,?DlgPrefix) :-
  ?IPSetToken := label("Token for IP allocation/?DlgPrefix($Version)"),
  {
    link($IPSetToken).
    allocate($Prcpl,$Prefix).
    label("IP allocation/$Prcpl($Version)").
  }.

defpost postIPAllocate(?Prcpl,?Prefix,?DlgPrefix) :-[ipAllocate(?Prcpl,?Prefix,?DlgPrefix)].

defcon makeIPTokenSet(?DlgPrefix) :-
  {
    label("Token for IP allocation/$DlgPrefix($Version)").
  }.

defpost postMakeIPTokenSet(?DlgPrefix):- [makeIPTokenSet(?DlgPrefix)].

defcon addDlgToken(?Token,?Prefix):-
  spec("link a token for allocated IP range"),
  {
    link($Token).
    label("Token for IP allocation/$Prefix($Version)").
  }.

defpost postDlgToken(?Token,?Prefix) :- [addDlgToken(?Token,?Prefix), addTokenToSubjectSet(?Token)].

defcon tagPrivilegePolicy() :-
  spec("Local policies on the delegation of tag access"),
  {
    tagPrivilege(?Tag, ?User) :-
      tagPrivilege(?Tag, ?User, _).

    tagPrivilege(?Tag, ?User, true) :-
      ?User := rootPrincipal(?Tag).

    tagPrivilege(?Tag, ?User, ?Delegatable) :-
      ?Owner := rootPrincipal(?Tag), 
      ?Owner: grantTagPriv(?Tag, ?User, ?Delegatable).

    tagPrivilege(?Tag, ?User, ?Delegatable) :-
      ?Delegator: grantTagPriv(?Tag, ?User, ?Delegatable),
      tagPrivilege(?Tag, ?Delegator, true).
    
    tagAccess(?Tag, ?Object):-
      ?Delegator: assignTag(?Object, ?Tag),
      tagPrivilege(?Tag, ?Delegator).

    label("tag-access-policy($PolicyVersion)").
  }.

definit tagPrivilegePolicy().

defpost postTagPrivilegePolicy() :- [tagPrivilegePolicy()].


defguard whoami() :-
  spec("Query principal id"),
  {
    principalId($Self).
    principalId(?X)?
  }.


defguard authorizeOwnPrefix(?User,?Prefix) :-
  spec('authorize if user owns prefix'),
  ?UserSubjectSet := label(?User, "subject(?User)($Version)"),
  ?OwnPrefixPolicy := label("own prefix policy($PolicyVersion)"),
  {
     link($UserSubjectSet).
     link($OwnPrefixPolicy).
     ownPrefix($User, $Prefix)?
  }.
