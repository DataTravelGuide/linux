#! /bin/sh

MARKER=$1
SOURCES=$2
SPECFILE=$3
BUILD=$4
BUILDID=$5
PATCHF="$SOURCES/Patch.include"
patchf="$SOURCES/patch.include"
SERIESF="$SOURCES/series"
clogf="$SOURCES/changelog"
# hide [redhat] entries from changelog
HIDE_REDHAT=1;
# override LC_TIME to avoid date conflicts when building the srpm
LC_TIME=
SUBLEVEL="$(echo $MARKER | cut -f 3 -d '.' | cut -f 1 -d '-')";
#SUBLEVEL="$(echo $MARKER | cut -f 3 -d '.')";
RCREV=$(echo $MARKER | cut -f 2 -d '-' -s | sed -e "s/rc//")
GITREV=$(echo $MARKER | cut -f 3 -d '-' -s | sed -e "s/git//")
LASTCOMMIT=$(cat lastcommit);
if [ -n "$RCREV" ]; then
	RELEASED_KERNEL="0";
	SUBLEVEL=$(($SUBLEVEL - 1));
else
	RELEASED_KERNEL="1";
	RCREV=0;
fi
if [ -z "$GITREV" ]; then
	GITREV=0;
fi
RPM_VERSION="2.6.$[SUBLEVEL+1]-0.$BUILD$BUILDID.el6";

touch $PATCHF $patchf
echo >$clogf

total="$(git log --pretty=oneline $MARKER.. |wc -l)"
git format-patch --no-renames -k --stdout $MARKER..|awk '
BEGIN{TYPE="PATCHJUNK"; count=1; dolog=0; }

	#convert subject line to a useable filename
	function subj_to_name(subject)
	{
		#strip off "Subject: "
		subject = substr(subject, 10);

		#need to get first word
		split(subject, a);
		pre = a[1];

		#if word matches foo: or [foo], then the patch is
		#good, otherwise stick a misc in front of it
		if (! match(pre, /:$|^\[.*\]$/)) {
			subject = "misc " subject;
		}

		name = subject;
		#keep cvs name all lower case, I forgot why
		if (SPECFILE == "") { name = tolower(name); }

		#do the actual filename conversion
		gsub(/[^a-zA-Z0-9_-]/,"-", name);
		gsub(/--*/, "-", name);
                gsub(/^[.-]*/, "", name);
                gsub(/[.-]*$/, "", name);

		#check for duplicate files and append a number to it
		patchname=name;
		num=2;
		while (! system("test -f " SOURCES "/" patchname ".patch")) {
			patchname=name "-" num;
			num=num+1;
        	}
		patchname = patchname ".patch";
	}

	# add an entry to changelog
	function changelog(subjectline, nameline)
	{
		subj = substr(subjectline, 10);
		gsub(/%/, "", subj)
		name = substr(nameline, 7);
		pos=match(name, /</);
		name=substr(name,1,pos-2);
		if ( HIDE_REDHAT == 1 ) {
			if ( subj ~ /^[\[]?redhat[:\]]/ ) {
				return;
			}
			# keep Fedora on the patch name but not on the changelog
			if ( subj ~ /^\[Fedora\]/ ) {
				gsub(/\[Fedora\] /, "", subj)
			}
		}
		bz=substr(BZ,11);
		meta = "";
		if (bz != "") {
			meta = " [" bz "]";
		}
		cve = substr(CVE, 6);
		if (cve != "") {
			if (meta != "") {
				meta = meta " {" cve "}";
			} else {
				meta = " {" cve "}";
			}
		}
		if ( COMMIT == LASTCOMMIT ) {
			dolog=1;
		} else {
			if (dolog == 1) {
				clog = "- " subj " (" name ")" meta;
				print clog >> CLOGF;
			}
		}
	}

	#special separator, close previous patch
	/^From / { if (TYPE=="PATCHJUNK") {
			COMMIT=substr($0, 6, 40);
			TYPE="HEADER";
			close(OUTF);
			next;
		} }

	#interesting header stuff
	/^From: / { if (TYPE=="HEADER") {
			namestr=$0;
			#check for mime encoding on the email headers
			#git uses utf-8 q encoding
			if ( $0 ~ /=\?utf-8\?q/ ) {
				#get rid of the meta utf-8 junk
				gsub(/=\?utf-8\?q\?/, "");
				gsub(/\?=/, "");

				#translate each char
				n=split($0, a, "=");
				namestr = sprintf("%s", a[1]);
				for (i = 2; i <= n; ++i) {
					utf = substr(a[i], 0, 2);
					c = strtonum("0x" utf);
					namestr = sprintf("%s%c%s", namestr, c, substr(a[i],3));
				}
			}
			NAMELINE=namestr; next;
		    }
	    }
	/^Date: / {if (TYPE=="HEADER") {DATELINE=$0; next; } }
	/^Subject: / { if (TYPE=="HEADER") {SUBJECTLINE=$0; next; } }
	/^Bugzilla: / { if (TYPE=="META") {BZ=$0; } }
	/^CVE: / { if (TYPE=="META") {CVE=$0; } }

	#blank line triggers end of header and to begin processing
	/^$/ { 
	    if (TYPE=="META") {
		#create the dynamic changelog entry
		changelog(SUBJECTLINE, NAMELINE);
		#reset cve values because they do not always exist
		CVE="";
		BZ="";
		TYPE="BODY";
	    }
	    if (TYPE=="HEADER") {
		subj_to_name(SUBJECTLINE);
		OUTF= SOURCES "/" patchname;

		#output patch commands for specfile
		print "Patch" pnum": " patchname >> PATCHF;
		print "ApplyPatch " patchname >> patchf;
		pnum=pnum+1;

		if (SPECFILE == "") { print patchname >> SERIESF; }

		printf "Creating kernel patches - (" count "/" total ")\r";
		count=count+1;

		print NAMELINE > OUTF;
		print DATELINE >> OUTF;
		print SUBJECTLINE >> OUTF;
		TYPE="META"; next;
	    }
	}

	#in order to handle overlapping keywords, we keep track of each
	#section of the patchfile and only process keywords in the correct section
	/^---$/ {
		if (TYPE=="META") {
			# no meta data found, just use the subject line to fill
			# the changelog
			changelog(SUBJECTLINE, NAMELINE);
			#reset cve values because they do not always exist
			CVE="";
			BZ="";
			TYPE="BODY";
		}
		if (TYPE=="BODY") {
			TYPE="PATCHSEP";
		}
	}
	/^diff --git/ { if (TYPE=="PATCHSEP") {print "" >> OUTF; TYPE="PATCH"; } }
	/^-- $/ { if (TYPE=="PATCH") { TYPE="PATCHJUNK"; } }

	#filter out stuff we do not care about
	{ if (TYPE == "PATCHSEP") { next; } }
	{ if (TYPE == "PATCHJUNK") { next; } }
	{ if (TYPE == "HEADER") { next; } }

	#print the rest
	{ print $0 >> OUTF; }
' SOURCES=$SOURCES PATCHF=$PATCHF patchf=$patchf SPECFILE=$SPECFILE \
	SERIESF=$SERIESF CLOGF=$clogf total=$total LASTCOMMIT=$LASTCOMMIT \
	HIDE_REDHAT=$HIDE_REDHAT

CONFIGS=configs/config.include
CONFIGS2=configs/config2.include
find configs/ -mindepth 1 -maxdepth 1 -name config-\* | grep -v merged | cut -f 2 -d '/' >$CONFIGS;
count=21;
rm -f $CONFIGS2;
for i in $(cat $CONFIGS); do
	echo "Source$count: $i" >>$CONFIGS2;
	count=$((count+1));
done

printf "Creating kernel patches - Done.    \n"

#the changelog was created in reverse order
#also remove the blank on top, if it exists
#left by the 'print version\n' logic above
cname="$(git var GIT_COMMITTER_IDENT |sed 's/>.*/>/')"
cdate="$(date +"%a %b %d %Y")"
cversion="[$RPM_VERSION]";
tac $clogf | sed "1{/^$/d; /^- /i\
* $cdate $cname $cversion
	}" > $clogf.rev

test -n "$SPECFILE" &&
        sed -i -e "/%%PATCH_LIST%%/r $PATCHF
        /%%PATCH_LIST%%/d
	/%%CONFIGS%%/r $CONFIGS2
	/%%CONFIGS%%/d
        /%%PATCH_APPLICATION%%/r $patchf
        /%%PATCH_APPLICATION%%/d
	/%%CHANGELOG%%/r $clogf.rev
	/%%CHANGELOG%%/d
	s/%%BUILD%%/$BUILD/
	s/%%SUBLEVEL%%/$SUBLEVEL/
	s/%%RCREV%%/$RCREV/
	s/%%GITREV%%/$GITREV/
	s/%%RELEASED_KERNEL%%/$RELEASED_KERNEL/" $SPECFILE
if [ -n "$BUILDID" ]; then
	sed -i -e "s/# % define buildid .local/%define buildid $BUILDID/" $SPECFILE;
fi

rm $PATCHF $patchf $clogf $clogf.rev $CONFIGS $CONFIGS2;

