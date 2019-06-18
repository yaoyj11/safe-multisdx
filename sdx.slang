import("../stitch.slang").
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
  ?IPToken := label("Token for IP allocation/?SrcPrefix($Version)"),
  ?AuthASPolicy := label("authz as policy($PolicyVersion)"),
  ?TagPrivPolicy := label("tag-access-policy($PolicyVersion)"),
  {
    link($IPToken).
    link($TagAclToken).
    link($AuthASPolicy).
    link($TagPrivPolicy).
    label("SD Policy Set/$SrcPrefix/$DstPrefix($Version)").
  }.

defpost postSdPolicySet(?SrcPrefix,?DstPrefix) :- [sdPolicySet(?SrcPrefix,?DstPrefix)].

defpost postASTagAclEntrySD(?Tag,?SrcPrefix,?DstPrefix) :- [sdxTagAclEntrySD(?Tag,?SrcPrefix,?DstPrefix), sdxTagAclEntrySD(?Tag, ?DstPrefix, ?SrcPrefix), sdPolicySet(?SrcPrefix, ?DstPrefix)].

defcon authorizeASPolicy():-
  {

    authorizedAS(?AS, ?DstIP):-
      authorizedASByUserAttr(?AS, ?DstIP).

    authorizedASByUserAttr(?AS, ?Prefix):-
      sdxTagAclEntry(?Tag, ?PrefixSet),
      ?Prefix <: ?PrefixSet,
      tagPrivilege(?Tag, ?AS).

    authorizedAS(?AS, ?FromIP, ?DstIP):-
      authorizedASByUserAttr(?AS, ?FromIP, ?DstIP).

    authorizedASByUserAttr(?AS, ?FromIP, ?DstIP):-
      sdxTagAclEntry(?Tag, ?SrcPrefix, ?DstPrefix),
      ?FromIP <: ?SrcPrefix,
      ?DstIP <: ?DstPrefix,
      tagPrivilege(?Tag, ?AS).

    label("authz as policy($PolicyVersion)").
  }.

defcon verifyASPolicy():-
  {
     verifyAS(?Owner, ?DstIP, ?AS):-
        ?Owner: authorizedAS(?AS, ?DstIP).

     verifyAS(?Owner, ?FromIP, ?DstIP, ?AS):-
        ?Owner: authorizedAS(?AS, ?FromIP, ?DstIP).

     label("verify as policy($PolicyVersion)").
  }.

definit verifyASPolicy().

defpost postAuthorizeASPolicy() :- [authorizeASPolicy()].

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

    routeSD(?SOwner,?DOwner,?SrcIP,?DstIP,?Path) :-
      ownPrefix(?SOwner,?SrcIP),
      authorizedAdvertiseSD(?SOwner,?DOwner,?SrcIPRange,?DstIPRange,?Path,$Self),
      ?SrcIP <: ?SrcIPRange,
      ?DstIP <: ?DstIPRange.

    authorizedAdvertiseSD(?SOwner,?DOwner,?SrcIP,?DstIP,?Path,?AS):-
      eq([?DOwner|?Tail],?Path),
      eq(?Tail,[]),
      ?DOwner: advertise(?SrcIP,?DstIP,?Path,?AS),
      ownPrefix(?DOwner,?DstIP).

    authorizedAdvertiseSD(?SOwner,?DOwner,?SrcIP,?DstIP,?Path,?AS):-
      eq([?Head|?Tail],?Path),
      ?Head:advertise(?SrcIP,?DstIP,?Path,?AS),
      ?DOwner: authorizedAS(?Head,?SrcIP,?DstIP),
      ?SOwner: authorizedAS(?Head,?SrcIP,?DstIP),
      authorizedAdvertiseSD(?SOwner,?DOwner,?SrcIPRange,?DstIPRange,?Tail,?Head),
      ?SrcIP <: ?SrcIPRange,
      ?DstIP <: ?DstIPRange.

    compliantPath(?Owner,?FromIP,?DstIP,?Path) :-
      eq([?Owner|?Tail],?Path),
      eq(?Tail,[]).

    compliantPath(?Owner, ?FromIP, ?DstIP, ?Path) :-
      eq([?Head|?Tail],?Path),
      ?Owner: authorizedAS(?Head, ?FromIP, ?DstIP),
      compliantPath(?Owner, ?FromIP, ?DstIP, ?Tail).

    label("routing policy($PolicyVersion)").
  }.

defpost postRoutingPolicy() :- [routingPolicy()].
definit routingPolicy().

defcon advertiseRoute(?DstIP,?Path,?Target,?Src,?Len):-
  ?PathToken := label("Path/?Src/?DstIP/?Len ($Version)"),
  ?TagSubjectSet := label("tags($Version)"),
  {
    link($PathToken).
    link($TagSubjectSet).
    advertise($DstIP,$Path,$Target).
    label("Advertise/$Target/$DstIP/$Len ($Version)").
  }.

defpost postAdvertise(?DstIP,?Path,?Target,?Src,?Len):- [advertiseRoute(?DstIP,?Path,?Target,?Src,?Len)].

defcon advertiseRouteSD(?FromIP,?DstIP,?Path,?Target,?Src,?Len):-
  ?PathToken := label("Path/?Src/?FromIP/?DstIP/?Len ($Version)"),
  ?TagSubjectSet := label("tags($Version)"),
  {
    link($PathToken).
    link($TagSubjectSet).
    advertise($FromIP,$DstIP,$Path,$Target).
    label("Advertise/$Target/$FromIP/$DstIP/$Len ($Version)").
  }.

defpost postAdvertiseSD(?FromIP,?DstIP,?Path,?Target,?Src,?Len):- [advertiseRouteSD(?FromIP,?DstIP,?Path,?Target,?Src,?Len)].

//can not use init here
defcon startRoute(?DstIP,?Path,?Target,?Len):-
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
    label("Advertise/$Target/$DstIP/$Len ($Version)").
  }.

defpost postInitRoute(?DstIP,?Path,?Target,?Len) :- [startRoute(?DstIP,?Path,?Target,?Len)].

defcon startRouteSD(?FromIP,?DstIP,?Path,?Target,?Len):-
  ?Token := label("Token for IP allocation/?DstIP($Version)"),
  ?AuthzASPolicy := label("authz as policy($PolicyVersion)"),
  ?AuthzASACL := label("sdxTagAclEntry(?FromIP)(?DstIP)($Version)"),
  ?TagPrivPolicy := label("tag-access-policy($PolicyVersion)"),
  {
    link($Token).
    link($AuthzASACL).
    link($AuthzASPolicy).
    link($TagPrivPolicy).
    advertise($FromIP,$DstIP,$Path,$Target).
    label("Advertise/$Target/$FromIP/$DstIP/$Len ($Version)").
  }.

defpost postInitRouteSD(?FromIP,?DstIP,?Path,?Target,?Len) :- [startRouteSD(?FromIP,?DstIP,?Path,?Target,?Len)].

defcon linkRoute(?Token,?DstIP,?Src,?Len):-
  spec("link a token for an advertised path"),
  {
    link($Token).
    label("Path/$Src/$DstIP/$Len ($Version)").
  }.

defcon addTokenPerIP(?Token,?DstIP):-
  {
    link($Token).
    label("Token for IP/$DstIP ($Version)").
  }.


defpost postPathToken(?Token,?DstIP,?Src,?Len) :- [linkRoute(?Token,?DstIP,?Src,?Len), addTokenPerIP(?Token,?DstIP)].

defcon linkRouteSD(?Token,?FromIP,?DstIP,?Src,?Len):-
  spec("link a token for an advertised path"),
  {
    link($Token).
    label("Path/$Src/$FromIP/$DstIP/$Len ($Version)").
  }.

defcon addTokenPerIPSD(?Token,?FromIP,?DstIP):-
  {
    link($Token).
    label("Token for IP/$FromIP/$DstIP ($Version)").
  }.


defpost postPathTokenSD(?Token,?FromIP,?DstIP,?Src,?Len) :- [linkRouteSD(?Token,?FromIP,?DstIP,?Src,?Len), addTokenPerIPSD(?Token,?FromIP,?DstIP)].

defguard verifyRoute(?Owner,?DstIP,?Path,?Token) :-
  ?RoutingPolicyRef := label("routing policy($PolicyVersion)"),
  ?OwnPrefixPolicy := label("own prefix policy($PolicyVersion)"),
  {
    link($OwnPrefixPolicy).
    link($RoutingPolicyRef).
    link($Token).
    route($Owner, $DstIP,$Path)?
  }.

defguard verifyRouteSD(?SOwner,?DOwner,?FromIP,?DstIP,?Path,?SToken,?DToken) :-
  ?RoutingPolicyRef := label("routing policy($PolicyVersion)"),
  ?OwnPrefixPolicy := label("own prefix policy($PolicyVersion)"),
  {
    link($OwnPrefixPolicy).
    link($RoutingPolicyRef).
    link($SToken).
    link($DToken).
    routeSD($SOwner,$DOwner,$FromIP,$DstIP,$Path)?
  }.

defguard verifyCompliantPath(?Owner,?FromIP,?DstIP,?Path,?Token1,?Token2) :-
  ?RoutingPolicyRef := label("routing policy($PolicyVersion)"),
  ?OwnPrefixPolicy := label("own prefix policy($PolicyVersion)"),
  ?SelfTagSet := label("tags($Version)"),
  {
    link($OwnPrefixPolicy).
    link($RoutingPolicyRef).
    link($Token1).
    link($Token2).
    link($SelfTagSet).
    compliantPath($Owner,$FromIP,$DstIP,$Path)?
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

defguard verifyASSD(?Owner, ?FromIP, ?DstIP, ?AS, ?Token):-
  ?VerifyASPolicyRef := label("verify as policy($PolicyVersion)"),
  ?ASTagSet := label(?AS, "tags($Version)"),
  {
    link($Token).
    link($VerifyASPolicyRef).
    link($ASTagSet).
    verifyAS($Owner, $FromIP, $DstIP, $AS)?
  }.

