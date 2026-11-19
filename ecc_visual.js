'use strict';
// Wyłącznie edukacyjne działania na publicznym G i małej przykładowej wartości d=5.
// Operacje modularne liczone dokładnie jako BigInt (bez konwersji do Number).
(() => {
  const p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
  const G = {
    x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
    y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
  };
  const mod = a => (a % p + p) % p;
  const inv = a => {
    let t = 0n, nt = 1n, r = p, nr = mod(a);
    while (nr) { const q = r / nr; [t, nt] = [nt, t - q * nt]; [r, nr] = [nr, r - q * nr]; }
    if (r !== 1n) throw Error('Brak odwrotności modularnej');
    return mod(t);
  };
  const add = (A, B) => {
    if (!A) return {result:B, lambda:null, action:'neutral'};
    if (!B) return {result:A, lambda:null, action:'neutral'};
    if (A.x === B.x && mod(A.y + B.y) === 0n) return {result:null,lambda:null, action:'infinity'};
    const double = A.x === B.x && A.y === B.y;
    const numerator = double ? 3n * A.x * A.x : B.y - A.y;
    const denominator = double ? 2n * A.y : B.x - A.x;
    const lambda = mod(numerator * inv(denominator));
    const x = mod(lambda * lambda - A.x - B.x);
    const y = mod(lambda * (A.x - x) - A.y);
    return {result:{x,y},lambda,action:double?'double':'add',numerator,denominator};
  };
  const multiples = [null,G];
  for(let i=2;i<=5;i++) multiples.push(add(multiples[i-1],G).result);
  const publicSteps = [
    {title:'Krok 1 · Podwojenie G',A:G,B:G,out:multiples[2],calculation:add(G,G),result:'2G'},
    {title:'Krok 2 · Podwojenie 2G',A:multiples[2],B:multiples[2],out:multiples[4],calculation:add(multiples[2],multiples[2]),result:'4G'},
    {title:'Krok 3 · Dodanie 4G + G',A:multiples[4],B:G,out:multiples[5],calculation:add(multiples[4],G),result:'5G = P'},
  ];
  const privateSteps = [
    {title:'Próba 1 · Sprawdzamy G',A:null,B:null,out:G,calculation:null,result:'1G'},
    ...[2,3,4,5].map(i=>({title:`Próba ${i} · ${i-1}G + G`,A:multiples[i-1],B:G,out:multiples[i],calculation:add(multiples[i-1],G),result:`${i}G`})),
  ];
  const current = {publiczny:0, prywatny:0};
  const hex = value => '0x'+value.toString(16).toUpperCase().padStart(64,'0');
  const short = value => hex(value).slice(0,15)+'…'+hex(value).slice(-10);
  const labelPoint = (point,name) => `<div><strong>${name}</strong> · x = ${hex(point.x)}<br>y = ${hex(point.y)}</div>`;
  // Rysunek na krzywej rzeczywistej y²=x³+7 stanowi analogię geometrii grupy.
  // Nie pokazuje rzeczywistych prostych w F_p: tam działania są modularne.
  function geometrySVG(kind) {
    const W=480,H=340,xMin=-2.1,xMax=3.15,yMin=-7,yMax=7;
    const sx = x => 30+(x-xMin)/(xMax-xMin)*(W-60);
    const sy = y => H-23-(y-yMin)/(yMax-yMin)*(H-46);
    const Pt = x => [x,Math.sqrt(Math.max(0,x*x*x+7))];
    const A=Pt(1), B=kind==='double'?A:Pt(2);
    const m=kind==='double'?(3*A[0]*A[0])/(2*A[1]):(B[1]-A[1])/(B[0]-A[0]);
    const x3=m*m-A[0]-B[0], y3=m*(A[0]-x3)-A[1];
    const T=[x3,y3], R=[x3,-y3];
    const curvePath = sign => {
      let path='';
      for(let i=0;i<=220;i++) {
        const x=-Math.cbrt(7)+ (xMax+Math.cbrt(7))*i/220;
        const y=sign*Math.sqrt(Math.max(0,x*x*x+7));
        path+=(i?'L':'M')+sx(x).toFixed(2)+' '+sy(y).toFixed(2)+' ';
      }
      return path;
    };
    const circle=(point,text,color,dx=9,dy=-9)=>`<circle cx="${sx(point[0])}" cy="${sy(point[1])}" r="5" fill="${color}" stroke="white" stroke-width="2"/><text x="${sx(point[0])+dx}" y="${sy(point[1])+dy}" fill="${color}" font-size="15" font-weight="700">${text}</text>`;
    const lineY = x => m*(x-A[0])+A[1];
    return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Schemat: ${kind==='double'?'styczna':'sieczna'}, trzeci punkt przecięcia i odbicie">
      <defs><clipPath id="clip-${kind}"><rect x="25" y="15" width="430" height="300"/></clipPath></defs>
      <path d="M${sx(xMin)} ${sy(0)}H${sx(xMax)} M${sx(0)} ${sy(yMin)}V${sy(yMax)}" stroke="#d9e2ee" stroke-width="1"/>
      <g clip-path="url(#clip-${kind})"><path d="${curvePath(1)}" fill="none" stroke="#2e70ba" stroke-width="2.5"/><path d="${curvePath(-1)}" fill="none" stroke="#2e70ba" stroke-width="2.5"/>
      <path d="M${sx(xMin)} ${sy(lineY(xMin))} L${sx(xMax)} ${sy(lineY(xMax))}" stroke="#d37c20" stroke-width="2"/>
      <path d="M${sx(x3)} ${sy(y3)}L${sx(x3)} ${sy(-y3)}" stroke="#188369" stroke-dasharray="6 4" stroke-width="2"/></g>
      ${circle(A,'A','#9b376f',-20,-12)} ${kind==='add'?circle(B,'B','#9b376f',10,-10):''} ${circle(T,'T','#cb7115',8,18)} ${circle(R,'A+B','#137b60',9,-12)}
      <text x="245" y="22" font-size="13" fill="#567087">y² = x³ + 7 (ℝ)</text>
    </svg>`;
  }
  // Zbiór prawdziwych współrzędnych secp256k1: punkty na osi x/y są tylko
  // umieszczone w kwadracie [0,p)². Nie łączymy ich mylącą euklidesową prostą.
  const normalized = n => Number((n*100000n)/p)/100000;
  function finiteFieldSVG(step) {
    const W=480,H=340, margin=39, len=255;
    const x=n=> margin+normalized(n)*len;
    const y=n=> H-margin-normalized(n)*len;
    const highlighted=[step.A,step.B,step.out].filter(Boolean);
    const base=multiples.slice(1).map((v,i)=>{
      const selected=highlighted.some(t=>t.x===v.x && t.y===v.y);
      return `<circle cx="${x(v.x)}" cy="${y(v.y)}" r="${selected?7:4.5}" fill="${selected?'#176fbb':'#8ca8c9'}" stroke="white" stroke-width="1.5"/><text x="${x(v.x)+8}" y="${y(v.y)-7}" font-size="15" fill="#1b486f">${i+1}G</text>`;
    }).join('');
    return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Rzeczywiste punkty G do 5G na secp256k1, współrzędne skalowane do przedziału od 0 do p">
      <rect x="${margin}" y="${margin}" width="${len}" height="${len}" fill="#f7faff" stroke="#a6bdd4"/>
      <text x="${margin}" y="28" fill="#546b87" font-size="14">Rzeczywiste punkty secp256k1</text>
      <text x="${margin}" y="${H-20}" font-size="13" fill="#5c7593">0</text><text x="${margin+len-8}" y="${H-20}" font-size="13" fill="#5c7593">p</text>
      <text x="${margin-19}" y="${margin+5}" font-size="13" fill="#5c7593">p</text><text x="${margin+len+12}" y="${H-margin+4}" font-size="13" fill="#5c7593">x</text>
      <text x="${margin-23}" y="${margin-9}" font-size="13" fill="#5c7593">y</text>${base}
    </svg>`;
  }
  function render(mode){
    const arr=mode==='publiczny'?publicSteps:privateSteps;
    const i=current[mode], s=arr[i], el=document.getElementById(mode==='publiczny'?'publicWalkthrough':'privateWalkthrough');
    if(!el)return;
    const isGuess=mode==='prywatny';
    const found=isGuess && i===4;
    const operation=s.calculation;
    const explanation=!operation?'<p>Na początku znamy publiczny punkt bazowy G, bez wykonywania dodawania.</p>':`<p>${operation.action==='double'?'Podwojenie punktu: obliczamy nachylenie stycznej za pomocą odwrotności modularnej.':'Dodanie dwóch punktów: obliczamy nachylenie siecznej za pomocą odwrotności modularnej.'}</p>
    <div class="ecc-formula">λ ≡ ${operation.action==='double'?'(3·x₁²) · (2·y₁)⁻¹':'(y₂ − y₁) · (x₂ − x₁)⁻¹'} (mod p)<br>x₃ ≡ λ² − x₁ − x₂ (mod p)<br>y₃ ≡ λ(x₁ − x₃) − y₁ (mod p)</div>
    <details><summary>Pokaż dokładną wartość nachylenia λ (hex)</summary><div class="ecc-hex">λ = ${hex(operation.lambda)}</div></details>`;
    const chartKind=operation?.action==='double'?'double':'add';
    const points=`<div class="point-info">${s.A?labelPoint(s.A,'A')+'<br>':''}${s.B?labelPoint(s.B,'B')+'<br>':''}${labelPoint(s.out,s.result)}</div>`;
    const status=isGuess?`<p class="${found?'result':'ecc-note'}">${found?'Znaleziono: 5G = P, więc w tym demonstracyjnym przykładzie d = 5.':`${i+1}G ≠ P — sprawdzamy dalej.`}</p>`:'<p class="result">Wynik wyznaczono dokładnie w polu secp256k1 (mod p).</p>';
    el.innerHTML=`<div class="walk-head"><span class="step-progress">Etap ${i+1} / ${arr.length}</span><div class="walk-buttons"><button type="button" class="secondary" data-prev ${i===0?'disabled':''}>Wstecz</button><button type="button" class="secondary" data-next ${i===arr.length-1?'disabled':''}>Dalej</button></div></div>
    <h3 class="walk-step-title">${s.title}</h3>${explanation}
    <div class="ecc-visual-grid">
      <figure class="ecc-figure">${geometrySVG(chartKind)}<figcaption><strong>Geometria poglądowa.</strong> Styczna/sieczna → trzeci punkt T → odbicie dające sumę. Rysunek nad ℝ, nie jest wykresem operacji modulo p.</figcaption></figure>
      <figure class="ecc-figure">${finiteFieldSVG(s)}<figcaption><strong>Dokładne punkty secp256k1.</strong> Pozycje odpowiadają współrzędnym x,y przeskalowanym z [0,p). W polu skończonym nie ma ciągłej krzywej do narysowania.</figcaption></figure>
    </div><details><summary>Współrzędne punktów (dokładne, hex)</summary>${points}</details>${status}
    <p class="ecc-note">Parametry: p = ${hex(p)}, a = 0, b = 7. W obu demonstracjach G jest rzeczywistym punktem bazowym secp256k1. Wszystkie obliczenia modularne wykonywane są na BigInt.</p>`;
    el.querySelector('[data-prev]').addEventListener('click',()=>{current[mode]--;render(mode)});
    el.querySelector('[data-next]').addEventListener('click',()=>{current[mode]++;render(mode)});
  }
  // Matematyczne testy spójności niezależne od wyświetlania wykresów.
  if(mod(G.y*G.y-G.x*G.x*G.x-7n)!==0n) throw Error('G nie należy do secp256k1');
  if(multiples[5].x!==publicSteps[2].out.x || multiples[5].y!==publicSteps[2].out.y) throw Error('Błąd 5G');
  render('publiczny');render('prywatny');
})();
