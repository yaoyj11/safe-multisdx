import("./stitch-all.slang").
//cannot use as tag here

defcon sdxTagAclEntry(?Tag,?Prefix) :-
  spec("user as tag access control list"),
  {
    sdxTagAclEntry($Tag,$Prefix).
    label("sdxTagAclEntry($Prefix)($Version)").
  }.

defpost postASTagAclEntry(?Tag,?Prefix) :- [sdxTagAclEntry(?Tag,?Prefix)].

defcon sdxTagAclEntrySD(?Tag, ?SrcPrefix, ?DstPrefix) :-
  spec("user as tag access control list"),
  {
    sdxTagAclEntry($Tag, $SrcPrefix, $DstPrefix).
    label("sdxTagAclEntry($SrcPrefix)($DstPrefix)($Version)").
  }.

defcon sdPolicySet(?SrcPrefix,?DstPrefix) :-
  ?TagAclToken := label("sdxTagAclEntry(?SrcPrefix)(?DstPrefix)($Version)"),
  ?AuthASPolicy := label("authz as policy($PolicyVersion)"),
  ?TagPrivPolicy := label("tag-access-policy($PolicyVersion)"),
  {
    link($TagAclToken).
    link($AuthASPolicy).
    link($TagPrivPolicy).
    label("SD Policy Set/$SrcPrefix/$DstPrefix($Version)").
  }.

defpost postASTagAclEntrySD(?Tag,?SrcPrefix,?DstPrefix) :- [sdxTagAclEntrySD(?Tag,?SrcPrefix,?DstPrefix)].

defpost postSdPolicySet(?SrcPrefix,?DstPrefix) :- [sdPolicySet(?SrcPrefix,?DstPrefix)].

defcon authorizeASPolicy():-
  {

    authorizedAS(?AS, ?DstIP):-
      authorizedASByUserAttr(?AS, ?DstIP).

    authorizedASByUserAttr(?AS, ?Prefix):-
      sdxTagAclEntry(?Tag, ?PrefixSet),
      ?Prefix <: ?PrefixSet,
      tagPrivilege(?Tag, ?AS).

    authorizedAS(?AS, ?SrcIP, ?DstIP):-
      authorizedASByUserAttr(?AS, ?SrcIP, ?DstIP).

    authorizedASByUserAttr(?AS, ?SrcIP, ?DstIP):-
      sdxTagAclEntry(?Tag, ?SrcPrefix, ?DstPrefix),
      ?SrcIP <: ?SrcPrefix,
      ?DstIP <: ?DstPrefix,
      tagPrivilege(?Tag, ?AS).

    label("authz as policy($PolicyVersion)").
  }.

defpost postAuthorizeASPolicy() :- [authorizeASPolicy()].

defcon verifyASPolicy():-
  {
     verifyAS(?Owner, ?DstIP, ?AS):-
        ?Owner: authorizedAS(?AS, ?DstIP).

     verifyAS(?Owner, ?SrcIP, ?DstIP, ?AS):-
        ?Owner: authorizedAS(?AS, ?SrcIP, ?DstIP).

     label("verify as policy($PolicyVersion)").
  }.

definit verifyASPolicy().

defpost postVerifyASPolicy() :- [verifyASPolicy()].

defcon routingPolicy() :-
  {
    route(?Owner,?DstIP,?Path) :-
      authorizedAdvertise(?Owner,?DstIPRange,?Path,$Self),
      ?DstIP <: ?DstIPRange.

    authorizedAdvertise(?Owner,?DstIP,?Path,?AS):-
      eq([?Owner|?Tail],?Path),
      eq(?Tail,[]),
      ?Owner: advertise(?DstIP,?Path,?AS),
      ownPrefix(?Owner,?DstIP).

    authorizedAdvertise(?Owner,?DstIP,?Path,?AS):-
      eq([?Head|?Tail],?Path),
      ?Head:advertise(?DstIP,?Path,?AS),
      ?Owner: authorizedAS(?Head, ?DstIP),
      authorizedAdvertise(?Owner,?DstIPRange,?Tail,?Head),
      ?DstIP <: ?DstIPRange.

    route(?Owner,?SrcIP,?DstIP,?Path) :-
      authorizedAdvertise(?Owner,?SrcIPRange,?DstIPRange,?Path,$Self),
      ?SrcIP <: ?SrcIPRange,
      ?DstIP <: ?DstIPRange.

    authorizedAdvertise(?Owner,?SrcIP,?DstIP,?Path,?AS):-
      eq([?Owner|?Tail],?Path),
      eq(?Tail,[]),
      ?Owner: advertise(?SrcIP,?DstIP,?Path,?AS),
      ownPrefix(?Owner,?DstIP).

    authorizedAdvertise(?Owner,?SrcIP,?DstIP,?Path,?AS):-
      eq([?Head|?Tail],?Path),
      ?Head:advertise(?SrcIP,?DstIP,?Path,?AS),
      ?Owner: authorizedAS(?Head,?SrcIP,?DstIP),
      authorizedAdvertise(?Owner,?SrcIPRange,?DstIPRange,?Tail,?Head),
      ?SrcIP <: ?SrcIPRange,
      ?DstIP <: ?DstIPRange.

    compliantPath(?SrcOwner,?SrcIP,?DstIP,?Path) :-
      eq([?DstOwner|?Tail],?Path),
      eq(?Tail,[]).

    compliantPath(?SrcOwner,?SrcIP,?DstIP,?Path) :-
      eq([?SrcOwner|?Tail],?Path),
      compliantPath(?SrcOwner, ?SrcIP, ?DstIP, ?Tail).

    compliantPath(?SrcOwner, ?SrcIP, ?DstIP, ?Path) :-
      eq([?Head|?Tail],?Path),
      eq(?Tail,[]),
      ?SrcOwner: authorizedAS(?Head, ?SrcIP, ?DstIP).

    compliantPath(?SrcOwner, ?SrcIP, ?DstIP, ?Path) :-
      eq([?Head|?Tail],?Path),
      ?SrcOwner: authorizedAS(?Head, ?SrcIP, ?DstIP),
      compliantPath(?SrcOwner, ?SrcIP, ?DstIP, ?Tail).

    label("routing policy($PolicyVersion)").
  }.

defpost postRoutingPolicy() :- [routingPolicy()].
definit routingPolicy().

defcon advertiseRoute(?DstIP,?Path,?Target,?Token):-
  ?TagSubjectSet := label("tags($Version)"),
  {
    link($Token).
    link($TagSubjectSet).
    advertise($DstIP,$Path,$Target).
    label("Advertise/$Target/$DstIP($Version)").
  }.

defpost postAdvertise(?DstIP,?Path,?Target,?Token):- [advertiseRoute(?DstIP,?Path,?Target,?Token)].

defcon advertiseRouteSD(?SrcIP,?DstIP,?Path,?Target,?Token):-
  ?TagSubjectSet := label("tags($Version)"),
  {
    link($Token).
    link($TagSubjectSet).
    advertise($SrcIP,$DstIP,$Path,$Target).
    label("Advertise/$Target/$SrcIP/$DstIP($Version)").
  }.

defpost postAdvertiseSD(?SrcIP,?DstIP,?Path,?Target,?Token):- [advertiseRouteSD(?SrcIP,?DstIP,?Path,?Target,?Token)].

//can not use init here
defcon startRoute(?DstIP,?Path,?Target):-
  ?Token := label("Token for IP allocation/?DstIP($Version)"),
  ?AuthzASPolicy := label("authz as policy($PolicyVersion)"),
  ?AuthzASACL := label("sdxTagAclEntry(?DstIP)($Version)"),
  ?TagPrivPolicy := label("tag-access-policy($PolicyVersion)"),
  {
    link($Token).
    link($AuthzASACL).
    link($AuthzASPolicy).
    link($TagPrivPolicy).
    advertise($DstIP,$Path,$Target).
    label("Advertise/$Target/$DstIP($Version)").
  }.

defpost postStartRoute(?DstIP,?Path,?Target) :- [startRoute(?DstIP,?Path,?Target)].

defcon startRouteSD(?SrcIP,?DstIP,?Path,?Target):-
  ?Token := label("Token for IP allocation/?DstIP($Version)"),
  ?AuthzASPolicy := label("authz as policy($PolicyVersion)"),
  ?AuthzASACL := label("sdxTagAclEntry(?SrcIP)(?DstIP)($Version)"),
  ?TagPrivPolicy := label("tag-access-policy($PolicyVersion)"),
  {
    link($Token).
    link($AuthzASACL).
    link($AuthzASPolicy).
    link($TagPrivPolicy).
    advertise($SrcIP,$DstIP,$Path,$Target).
    label("Advertise/$Target/$SrcIP/$DstIP($Version)").
  }.

defpost postStartRouteSD(?SrcIP,?DstIP,?Path,?Target) :- [startRouteSD(?SrcIP,?DstIP,?Path,?Target)].

defguard verifyRoute(?Owner,?DstIP,?Path,?Token) :-
  ?RoutingPolicyRef := label("routing policy($PolicyVersion)"),
  ?OwnPrefixPolicy := label("own prefix policy($PolicyVersion)"),
  {
    link($OwnPrefixPolicy).
    link($RoutingPolicyRef).
    link($Token).
    route($Owner, $DstIP,$Path)?
  }.

defguard verifyRouteSD(?Owner,?SrcIP,?DstIP,?Path,?Token) :-
  ?RoutingPolicyRef := label("routing policy($PolicyVersion)"),
  ?OwnPrefixPolicy := label("own prefix policy($PolicyVersion)"),
  {
    link($OwnPrefixPolicy).
    link($RoutingPolicyRef).
    link($Token).
    route($Owner,$SrcIP,$DstIP,$Path)?
  }.

defguard verifyCompliantPath(?Owner,?SrcIP,?DstIP,?Path,?PolicyToken, ?RouteToken) :-
  ?RoutingPolicyRef := label("routing policy($PolicyVersion)"),
  ?OwnPrefixPolicy := label("own prefix policy($PolicyVersion)"),
  ?SelfTagSet := label("tags($Version)"),
  {
    link($OwnPrefixPolicy).
    link($RoutingPolicyRef).
    link($PolicyToken).
    link($RouteToken).
    link($SelfTagSet).
    compliantPath($Owner,$SrcIP,$DstIP,$Path)?
  }.

defguard verifyAS(?Owner, ?DstIP, ?AS, ?Token):-
  ?VerifyASPolicyRef := label("verify as policy($PolicyVersion)"),
  ?ASTagSet := label(?AS, "tags($Version)"),
  {
    link($Token).
    link($VerifyASPolicyRef).
    link($ASTagSet).
    verifyAS($Owner, $DstIP, $AS)?
  }.

defguard verifyASSD(?Owner, ?SrcIP, ?DstIP, ?AS, ?Token):-
  ?VerifyASPolicyRef := label("verify as policy($PolicyVersion)"),
  ?ASTagSet := label(?AS, "tags($Version)"),
  {
    link($Token).
    link($VerifyASPolicyRef).
    link($ASTagSet).
    verifyAS($Owner, $SrcIP, $DstIP, $AS)?
  }.

